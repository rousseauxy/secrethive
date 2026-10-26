using System.Collections.Concurrent;
using System.Net;
using System.Security.Claims;
using SecretHive.Application.Ports;
using SecretHive.Domain.Entities;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;

namespace SecretHive.Web.SignIn;

/// <summary>
/// Checks access tokens from the providers a super admin trusts for the API: an application's client-credentials token from
/// Entra ID, Authentik or Keycloak, or a CI job's token from GitLab or GitHub Actions. The issuer's discovery document and
/// signing keys are fetched once and kept, refreshed twice a day, and fetched again when a token names a key they do not
/// have - which is how a provider's key rollover looks from here.
/// </summary>
public sealed class ApiTokenValidator(IServiceScopeFactory scopes, TimeProvider time, ILogger<ApiTokenValidator> logger) : IExternalTokenValidator, IDisposable
{
    /// <summary>Asymmetric algorithms only: a token must be signed with the issuer's private key, never a shared secret or none.</summary>
    private static readonly string[] Algorithms =
    [
        SecurityAlgorithms.RsaSha256, SecurityAlgorithms.RsaSha384, SecurityAlgorithms.RsaSha512,
        SecurityAlgorithms.RsaSsaPssSha256, SecurityAlgorithms.RsaSsaPssSha384, SecurityAlgorithms.RsaSsaPssSha512,
        SecurityAlgorithms.EcdsaSha256, SecurityAlgorithms.EcdsaSha384, SecurityAlgorithms.EcdsaSha512,
    ];

    /// <summary>
    /// A token valid for longer than this is refused whatever its signature: the point of these tokens over a stored key is
    /// that a leaked one stops working soon. Entra's last about an hour, CI job tokens as long as the job.
    /// </summary>
    public static readonly TimeSpan MaxLifetime = TimeSpan.FromHours(24);

    private static readonly TimeSpan MetadataLifetime = TimeSpan.FromHours(12);

    private static readonly string[] CallerClaims = ["azp", "client_id", "appid", "sub"];

    private readonly ConcurrentDictionary<int, IssuerMetadata> metadata = new();
    private readonly HttpClient http = new(new SocketsHttpHandler { PooledConnectionLifetime = TimeSpan.FromMinutes(5) }) { Timeout = TimeSpan.FromSeconds(15) };

    /// <summary>
    /// How soon after fetching an issuer's keys an unknown key id may fetch them again. Bounds what a stream of tokens with
    /// made-up key ids can make SecretHive do to the issuer: one fetch per interval per provider.
    /// </summary>
    public TimeSpan KeyRefreshInterval { get; set; } = TimeSpan.FromSeconds(30);

    public void Dispose() => http.Dispose();

    public async Task<ExternalTokenCheck> ValidateAsync(string token, CancellationToken cancellationToken)
    {
        var handler = new JsonWebTokenHandler { MapInboundClaims = false };
        JsonWebToken jwt;
        try
        {
            jwt = handler.ReadJsonWebToken(token);
        }
        catch (Exception e) when (e is ArgumentException or SecurityTokenException)
        {
            return ExternalTokenCheck.Refused(null, "not a readable token");
        }

        if (!Algorithms.Contains(jwt.Alg, StringComparer.Ordinal))
        {
            return ExternalTokenCheck.Refused(null, "not signed with an accepted algorithm");
        }

        // The issuer read before the signature is checked only chooses which provider's keys to check it with.
        var issuer = NormalIssuer(jwt.Issuer);
        IReadOnlyList<OidcProvider> providers;
        await using (var scope = scopes.CreateAsyncScope())
        {
            var all = await scope.ServiceProvider.GetRequiredService<IOidcProviderStore>().ListAsync(cancellationToken);

            // The keys of a provider that was deleted, or no longer accepts tokens, are not kept until the next restart.
            foreach (var key in metadata.Keys.Where(key => !all.Any(p => p.Key == key && p.AcceptApiTokens)).ToList())
            {
                metadata.TryRemove(key, out _);
            }

            providers = [.. all.Where(p => p.AcceptApiTokens && issuer.Length > 0 && NormalIssuer(p.Authority) == issuer)];
        }

        if (providers.Count == 0)
        {
            return ExternalTokenCheck.Refused(null, "issuer not trusted for API tokens");
        }

        ExternalTokenCheck? refused = null;
        foreach (var provider in providers)
        {
            var check = await ValidateWithAsync(handler, provider, token, cancellationToken);
            if (check.Identity is not null)
            {
                return check;
            }

            refused ??= check;
        }

        return refused!;
    }

    private async Task<ExternalTokenCheck> ValidateWithAsync(JsonWebTokenHandler handler, OidcProvider provider, string token, CancellationToken cancellationToken)
    {
        var audiences = OidcProvider.ParseAudiences(provider.ApiAudiences);
        var required = OidcProvider.ParseRequiredClaims(provider.ApiRequiredClaims);
        if (audiences.Count == 0 || required is null)
        {
            return ExternalTokenCheck.Refused(provider.Slug, "provider has no audience or unreadable required claims");
        }

        var issuer = metadata.AddOrUpdate(
            provider.Key,
            _ => new IssuerMetadata(provider),
            (_, existing) => existing.Version == provider.UpdatedUtc && existing.Authority == provider.Authority ? existing : new IssuerMetadata(provider));

        OpenIdConnectConfiguration configuration;
        try
        {
            configuration = await issuer.GetAsync(http, time, refreshKeys: false, KeyRefreshInterval, cancellationToken);
        }
        catch (Exception e) when (e is not OperationCanceledException)
        {
            logger.LogWarning(e, "Could not read the discovery document of provider {Provider} at {Authority} to check an API token", provider.Slug, provider.Authority);
            return ExternalTokenCheck.Refused(provider.Slug, "issuer metadata unavailable");
        }

        var result = await handler.ValidateTokenAsync(token, Parameters(configuration, audiences));
        if (!result.IsValid && result.Exception is SecurityTokenSignatureKeyNotFoundException)
        {
            try
            {
                configuration = await issuer.GetAsync(http, time, refreshKeys: true, KeyRefreshInterval, cancellationToken);
                result = await handler.ValidateTokenAsync(token, Parameters(configuration, audiences));
            }
            catch (Exception e) when (e is not OperationCanceledException)
            {
                logger.LogWarning(e, "Could not refresh the signing keys of provider {Provider}", provider.Slug);
            }
        }

        if (!result.IsValid)
        {
            return ExternalTokenCheck.Refused(provider.Slug, Reason(result.Exception));
        }

        var validated = (JsonWebToken)result.SecurityToken;

        // An ID token from someone's sign-in carries a nonce; an access token does not. With the client id as the audience,
        // which is what Entra and Authentik put in both, this is what keeps an ID token from passing as an API token.
        if (validated.TryGetPayloadValue<string>("nonce", out _))
        {
            return ExternalTokenCheck.Refused(provider.Slug, "an ID token, not an access token");
        }

        // Measured over the whole life the token was issued for, from when it was issued or became valid, not only over what
        // is left of it: a token minted for thirty hours is refused for all thirty, not only for its first six. A token that
        // says neither when it was issued nor from when it is valid is held to what it has left.
        var start = validated.TryGetPayloadValue<long>("iat", out _) ? validated.IssuedAt
            : validated.TryGetPayloadValue<long>("nbf", out _) ? validated.ValidFrom
            : time.GetUtcNow().UtcDateTime;
        if (validated.ValidTo - start > MaxLifetime || validated.ValidTo - time.GetUtcNow().UtcDateTime > MaxLifetime)
        {
            return ExternalTokenCheck.Refused(provider.Slug, "valid for longer than a day");
        }

        var claims = validated.Claims.ToList();
        foreach (var (name, values) in required)
        {
            if (!claims.Any(c => c.Type == name && values.Any(value => OidcProvider.ClaimValueMatches(value, c.Value))))
            {
                return ExternalTokenCheck.Refused(provider.Slug, $"required claim {name} missing or different");
            }
        }

        var groups = provider.GroupsClaim.Length == 0
            ? []
            : claims.Where(c => c.Type == provider.GroupsClaim).Select(c => c.Value).Where(v => v.Length > 0).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        return ExternalTokenCheck.Accepted(new ExternalTokenIdentity(provider.Key, provider.Slug, Caller(claims), groups));
    }

    private static TokenValidationParameters Parameters(OpenIdConnectConfiguration configuration, IReadOnlyList<string> audiences) => new()
    {
        ValidIssuer = configuration.Issuer,
        ValidateIssuer = true,
        ValidAudiences = audiences,
        ValidateAudience = true,
        IssuerSigningKeys = configuration.SigningKeys,
        ValidateIssuerSigningKey = true,
        ValidAlgorithms = Algorithms,
        RequireSignedTokens = true,
        RequireExpirationTime = true,
        ValidateLifetime = true,
        ClockSkew = TimeSpan.FromMinutes(1),
    };

    private static string Reason(Exception? exception) => exception switch
    {
        SecurityTokenExpiredException => "expired",
        SecurityTokenNotYetValidException => "not yet valid",
        SecurityTokenInvalidAudienceException => "wrong audience",
        SecurityTokenInvalidIssuerException => "wrong issuer",
        SecurityTokenSignatureKeyNotFoundException => "signed with an unknown key",
        SecurityTokenInvalidSignatureException => "invalid signature",
        SecurityTokenInvalidAlgorithmException => "not signed with an accepted algorithm",
        SecurityTokenNoExpirationException => "no expiry",
        _ => "invalid",
    };

    /// <summary>The calling application or subject, cut to something a log line can hold and nothing that breaks one.</summary>
    private static string Caller(IReadOnlyList<Claim> claims)
    {
        var value = CallerClaims.Select(name => claims.FirstOrDefault(c => c.Type == name)?.Value).FirstOrDefault(v => !string.IsNullOrWhiteSpace(v)) ?? "unknown";
        var clean = new string([.. value.Where(c => !char.IsControl(c) && !char.IsWhiteSpace(c))]);
        return clean.Length > 128 ? clean[..128] : clean;
    }

    private static string NormalIssuer(string? issuer) => (issuer ?? "").Trim().TrimEnd('/');

    /// <summary>One provider's discovery document and keys, as last fetched, for the provider row as it was then.</summary>
    private sealed class IssuerMetadata(OidcProvider provider)
    {
        private readonly Lock sync = new();
        private Task<OpenIdConnectConfiguration>? fetching;
        private OpenIdConnectConfiguration? configuration;
        private DateTime fetchedUtc;

        public DateTime Version { get; } = provider.UpdatedUtc;

        public string Authority { get; } = provider.Authority;

        public async Task<OpenIdConnectConfiguration> GetAsync(HttpClient http, TimeProvider time, bool refreshKeys, TimeSpan keyRefreshInterval, CancellationToken cancellationToken)
        {
            if (configuration is { } current && !Stale(time.GetUtcNow().UtcDateTime, refreshKeys, keyRefreshInterval))
            {
                return current;
            }

            // Every request that finds the document stale waits for the same fetch, so a burst of API calls is one request to
            // the issuer. The fetch itself is not cancelled with any one of them.
            Task<OpenIdConnectConfiguration> task;
            lock (sync)
            {
                // Looked at again under the lock: a request that found nothing a moment ago may arrive just after that fetch
                // finished and was cleared, and must use its answer rather than start a second one.
                if (configuration is { } fetched && !Stale(time.GetUtcNow().UtcDateTime, refreshKeys, keyRefreshInterval))
                {
                    return fetched;
                }

                task = fetching ??= FetchAsync(http, time);
            }

            try
            {
                return await task.WaitAsync(cancellationToken);
            }
            finally
            {
                lock (sync)
                {
                    if (ReferenceEquals(fetching, task) && task.IsCompleted)
                    {
                        fetching = null;
                    }
                }
            }
        }

        private async Task<OpenIdConnectConfiguration> FetchAsync(HttpClient http, TimeProvider time)
        {
            // An issuer that just failed to answer is not asked again for a while: without this, every API call during its
            // outage would wait out the timeout.
            if (time.GetUtcNow().UtcDateTime - failedUtc < RetryAfterFailure)
            {
                return configuration ?? throw new InvalidOperationException("The issuer's discovery document could not be read a moment ago.");
            }

            try
            {
                var authority = new Uri(Authority);
                var retriever = new HttpDocumentRetriever(http) { RequireHttps = !(authority.IsLoopback || (IPAddress.TryParse(authority.Host, out var ip) && IPAddress.IsLoopback(ip))) };
                var fetched = await OpenIdConnectConfigurationRetriever.GetAsync(Authority.TrimEnd('/') + "/.well-known/openid-configuration", retriever, CancellationToken.None);
                configuration = fetched;
                fetchedUtc = time.GetUtcNow().UtcDateTime;
                return fetched;
            }
            catch (Exception) when (configuration is { } previous)
            {
                // Keys that worked an hour ago still check the tokens signed with them; an outage at the issuer should not
                // stop a pipeline whose token was issued before it.
                failedUtc = time.GetUtcNow().UtcDateTime;
                return previous;
            }
            catch (Exception)
            {
                failedUtc = time.GetUtcNow().UtcDateTime;
                throw;
            }
        }

        private static readonly TimeSpan RetryAfterFailure = TimeSpan.FromSeconds(30);

        private DateTime failedUtc = DateTime.MinValue;

        private bool Stale(DateTime now, bool refreshKeys, TimeSpan keyRefreshInterval) =>
            (now - fetchedUtc > MetadataLifetime || (refreshKeys && now - fetchedUtc >= keyRefreshInterval))
            && now - failedUtc >= RetryAfterFailure;
    }
}
