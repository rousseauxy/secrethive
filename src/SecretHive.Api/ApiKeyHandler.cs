using System.Globalization;
using System.Security.Claims;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using SecretHive.Application.Accounts;

namespace SecretHive.Api;

/// <summary>
/// A tool signing in with a key of its own, sent as <c>Authorization: Bearer shv_…</c>. The request then acts as the
/// key's owner, inside the key's limits. A key that does not check out is no credential: the answer is 401, and when
/// the key was a real one that has ended, the attempt is on record.
/// </summary>
public sealed class ApiKeyHandler(IOptionsMonitor<AuthenticationSchemeOptions> options, ILoggerFactory logger, UrlEncoder encoder)
    : AuthenticationHandler<AuthenticationSchemeOptions>(options, logger, encoder)
{
    public const string SchemeName = "ApiKey";
    public const string UserClaim = "sh:user";
    public const string KeyClaim = "sh:key";
    public const string VaultClaim = "sh:key-vault";
    public const string MaxRoleClaim = "sh:key-max";

    /// <summary>Present when the key belongs to a service identity that holds the instance role Admin.</summary>
    public const string AdminServiceClaim = "sh:key-admin";

    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        var header = Request.Headers.Authorization.ToString();
        if (!header.StartsWith("Bearer ", StringComparison.Ordinal) || !KeyService.LooksLikeKey(header["Bearer ".Length..]))
        {
            return AuthenticateResult.NoResult();
        }

        var address = Context.Connection.RemoteIpAddress is { } remote ? (remote.IsIPv4MappedToIPv6 ? remote.MapToIPv4() : remote).ToString() : null;
        var keys = Context.RequestServices.GetRequiredService<KeyService>();
        if (await keys.AuthenticateAsync(header["Bearer ".Length..], address, Context.RequestAborted) is not { } identity)
        {
            return AuthenticateResult.Fail("That key is not valid.");
        }

        var claims = new List<Claim>
        {
            new(ClaimTypes.Name, identity.Owner.UserName),
            new(UserClaim, identity.Owner.Key.ToString(CultureInfo.InvariantCulture)),
            new(KeyClaim, identity.Key.Key.ToString(CultureInfo.InvariantCulture)),
        };
        if (identity.Key.VaultId is { } vault)
        {
            claims.Add(new Claim(VaultClaim, vault.ToString("N")));
        }

        if (identity.Key.MaxRole is { } max)
        {
            claims.Add(new Claim(MaxRoleClaim, max.ToString()));
        }

        // Read from the owner as it is now, on every request: taking the role away ends it for every key at once. A key
        // narrowed to one vault stays narrowed: it is no administrator of the whole instance.
        if (identity.Owner is { IsService: true, Role: SecretHive.Domain.Entities.UserRole.Admin } && identity.Key.VaultId is null)
        {
            claims.Add(new Claim(AdminServiceClaim, "true"));
        }

        return AuthenticateResult.Success(new AuthenticationTicket(new ClaimsPrincipal(new ClaimsIdentity(claims, SchemeName)), SchemeName));
    }
}
