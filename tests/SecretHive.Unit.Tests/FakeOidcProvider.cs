using System.Collections.Concurrent;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace SecretHive.Unit.Tests;

/// <summary>Who the fake provider signs in as next: the person at the provider's login screen.</summary>
public sealed record FakeIdentity(string Subject, string? UserName = null, string? Email = null, string? Name = null, string[]? Groups = null, bool? EmailVerified = null);

/// <summary>
/// A minimal OpenID Connect provider on a loopback port: discovery, keys, authorize, token and user info, with the checks
/// that matter to a client - redirect URI, client secret, PKCE, nonce - so a sign-in through it is a real code flow with a
/// signed ID token, not a shortcut around the server's own handler. The login screen is skipped: <see cref="Next"/> is who signs in.
/// </summary>
public sealed class FakeOidcProvider : IAsyncDisposable
{
    public const string ClientId = "secrethive-test";
    public const string ClientSecret = "generated-client-secret-0123456789";

    private readonly WebApplication app;
    private RsaSecurityKey signingKey;
    private readonly ConcurrentDictionary<string, Grant> codes = new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<string, FakeIdentity> accessTokens = new(StringComparer.Ordinal);
    private int tokenRequests;

    private FakeOidcProvider(WebApplication app, RsaSecurityKey signingKey)
    {
        this.app = app;
        this.signingKey = signingKey;
    }

    /// <summary>The issuer, without a trailing slash.</summary>
    public string Authority { get; private set; } = "";

    /// <summary>Who signs in at the next authorize request. Null answers <c>access_denied</c>, as a person cancelling would.</summary>
    public FakeIdentity? Next { get; set; }

    public int TokenRequests => tokenRequests;

    /// <summary>While true, discovery and the key set answer 503, as an issuer in an outage does.</summary>
    public bool Broken { get; set; }

    /// <summary>
    /// An access token as an issuer hands one to an application or a CI job: signed with the provider's current key, for
    /// <paramref name="audience"/>, with the claims given. The parameters after it make the ways a token goes wrong.
    /// </summary>
    /// <param name="issuer">An <c>iss</c> other than the provider's own, for tokens that only look like this issuer's.</param>
    /// <param name="audiences">Several audiences instead of <paramref name="audience"/>, as Entra and Keycloak send them.</param>
    /// <param name="omitKeyId">Sign with the current key but send no <c>kid</c>, as some issuers do.</param>
    /// <param name="noExpiry">Leave out <c>exp</c> altogether.</param>
    public string CreateAccessToken(
        string audience,
        IDictionary<string, object> claims,
        TimeSpan? lifetime = null,
        DateTime? expires = null,
        SecurityKey? key = null,
        string algorithm = SecurityAlgorithms.RsaSha256,
        string? issuer = null,
        IEnumerable<string>? audiences = null,
        bool omitKeyId = false,
        DateTime? notBefore = null,
        DateTime? issuedAt = null,
        bool noExpiry = false)
    {
        var now = DateTime.UtcNow;
        var payload = new Dictionary<string, object>(claims);
        if (audiences is not null)
        {
            payload["aud"] = audiences.ToArray();
        }

        var signingKeyToUse = key ?? (omitKeyId ? new RsaSecurityKey(signingKey.Rsa) : signingKey);
        var handler = new JsonWebTokenHandler { SetDefaultTimesOnTokenCreation = false };
        return handler.CreateToken(new SecurityTokenDescriptor
        {
            Issuer = issuer ?? Authority,
            Audience = audiences is null ? audience : null,
            IssuedAt = issuedAt ?? now.AddMinutes(-2),
            NotBefore = notBefore ?? now.AddMinutes(-2),
            Expires = noExpiry ? null : expires ?? now + (lifetime ?? TimeSpan.FromMinutes(10)),
            Claims = payload,
            SigningCredentials = new SigningCredentials(signingKeyToUse, algorithm),
        });
    }

    /// <summary>A key of the same kind with the provider's key id, which the provider never published: a forged signature.</summary>
    public static RsaSecurityKey ForgedKey(string keyId = "fake-key") => new(RSA.Create(2048)) { KeyId = keyId };

    /// <summary>Replaces the signing key under a new key id, as a provider's key rollover does; the old one is no longer published.</summary>
    public void RotateKey() => signingKey = new RsaSecurityKey(RSA.Create(2048)) { KeyId = "fake-key-" + Guid.NewGuid().ToString("N")[..8] };

    public static async Task<FakeOidcProvider> StartAsync()
    {
        var builder = WebApplication.CreateSlimBuilder();
        builder.Logging.ClearProviders();
        builder.WebHost.UseKestrel(k => k.Listen(IPAddress.Loopback, 0));
        var app = builder.Build();
        var rsa = RSA.Create(2048);
        var provider = new FakeOidcProvider(app, new RsaSecurityKey(rsa) { KeyId = "fake-key" });
        provider.Map();
        await app.StartAsync();
        var address = app.Services.GetRequiredService<IServer>().Features.Get<IServerAddressesFeature>()!.Addresses.First();
        provider.Authority = address.Replace("[::]", "127.0.0.1", StringComparison.Ordinal).TrimEnd('/');
        return provider;
    }

    public async ValueTask DisposeAsync()
    {
        await app.StopAsync();
        await app.DisposeAsync();
    }

    private void Map()
    {
        app.MapGet("/.well-known/openid-configuration", () =>
        {
            if (Broken)
            {
                return Results.StatusCode(StatusCodes.Status503ServiceUnavailable);
            }

            return Results.Json(new Dictionary<string, object>
            {
                ["issuer"] = Authority,
                ["authorization_endpoint"] = Authority + "/authorize",
                ["token_endpoint"] = Authority + "/token",
                ["userinfo_endpoint"] = Authority + "/userinfo",
                ["jwks_uri"] = Authority + "/jwks",
                ["response_types_supported"] = new[] { "code" },
                ["subject_types_supported"] = new[] { "public" },
                ["id_token_signing_alg_values_supported"] = new[] { "RS256" },
                ["code_challenge_methods_supported"] = new[] { "S256" },
            });
        });

        app.MapGet("/jwks", () =>
        {
            if (Broken)
            {
                return Results.StatusCode(StatusCodes.Status503ServiceUnavailable);
            }

            var parameters = signingKey.Rsa.ExportParameters(false);
            return Results.Json(new
            {
                keys = new[]
                {
                    new { kty = "RSA", use = "sig", alg = "RS256", kid = signingKey.KeyId, n = Base64UrlEncoder.Encode(parameters.Modulus), e = Base64UrlEncoder.Encode(parameters.Exponent) },
                },
            });
        });

        app.MapGet("/authorize", (HttpRequest request) =>
        {
            var query = request.Query;
            var redirect = query["redirect_uri"].ToString();
            var state = Uri.EscapeDataString(query["state"].ToString());
            if (query["client_id"] != ClientId || string.IsNullOrEmpty(redirect))
            {
                return Results.BadRequest("unknown client");
            }

            if (Next is not { } identity)
            {
                return Results.Redirect($"{redirect}?error=access_denied&state={state}");
            }

            var code = Guid.NewGuid().ToString("N");
            codes[code] = new Grant(identity, query["nonce"].ToString(), redirect, query["code_challenge"].ToString());
            return Results.Redirect($"{redirect}?code={code}&state={state}");
        });

        app.MapPost("/token", async (HttpRequest request) =>
        {
            Interlocked.Increment(ref tokenRequests);
            var form = await request.ReadFormAsync();
            var (clientId, secret) = ClientCredentials(request, form);
            if (clientId != ClientId || secret != ClientSecret)
            {
                return Results.Json(new { error = "invalid_client" }, statusCode: StatusCodes.Status401Unauthorized);
            }

            if (!codes.TryRemove(form["code"].ToString(), out var grant)
                || grant.RedirectUri != form["redirect_uri"].ToString()
                || grant.CodeChallenge != Base64UrlEncoder.Encode(SHA256.HashData(Encoding.ASCII.GetBytes(form["code_verifier"].ToString()))))
            {
                return Results.Json(new { error = "invalid_grant" }, statusCode: StatusCodes.Status400BadRequest);
            }

            var accessToken = Guid.NewGuid().ToString("N");
            accessTokens[accessToken] = grant.Identity;
            var claims = Claims(grant.Identity);
            claims["nonce"] = grant.Nonce;
            var idToken = new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor
            {
                Issuer = Authority,
                Audience = ClientId,
                IssuedAt = DateTime.UtcNow,
                NotBefore = DateTime.UtcNow.AddMinutes(-1),
                Expires = DateTime.UtcNow.AddMinutes(5),
                Claims = claims,
                SigningCredentials = new SigningCredentials(signingKey, SecurityAlgorithms.RsaSha256),
            });
            return Results.Json(new { access_token = accessToken, token_type = "Bearer", expires_in = 300, id_token = idToken });
        });

        app.MapGet("/userinfo", (HttpRequest request) =>
        {
            var header = request.Headers.Authorization.ToString();
            return header.StartsWith("Bearer ", StringComparison.Ordinal) && accessTokens.TryGetValue(header[7..], out var identity)
                ? Results.Json(Claims(identity))
                : Results.StatusCode(StatusCodes.Status401Unauthorized);
        });
    }

    private static Dictionary<string, object> Claims(FakeIdentity identity)
    {
        var claims = new Dictionary<string, object> { ["sub"] = identity.Subject };
        if (identity.UserName is not null)
        {
            claims["preferred_username"] = identity.UserName;
        }

        if (identity.Email is not null)
        {
            claims["email"] = identity.Email;
        }

        if (identity.Name is not null)
        {
            claims["name"] = identity.Name;
        }

        if (identity.EmailVerified is { } verified)
        {
            claims["email_verified"] = verified;
        }

        if (identity.Groups is not null)
        {
            claims["groups"] = identity.Groups;
        }

        return claims;
    }

    private static (string? ClientId, string? Secret) ClientCredentials(HttpRequest request, IFormCollection form)
    {
        var header = request.Headers.Authorization.ToString();
        if (header.StartsWith("Basic ", StringComparison.Ordinal))
        {
            var decoded = Encoding.UTF8.GetString(Convert.FromBase64String(header[6..]));
            var colon = decoded.IndexOf(':', StringComparison.Ordinal);
            return (Uri.UnescapeDataString(decoded[..colon]), Uri.UnescapeDataString(decoded[(colon + 1)..]));
        }

        return (form["client_id"].ToString(), form["client_secret"].ToString());
    }

    private sealed record Grant(FakeIdentity Identity, string Nonce, string RedirectUri, string CodeChallenge);
}
