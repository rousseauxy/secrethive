using System.Globalization;
using System.Security.Claims;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;
using SecretHive.Application.Accounts;
using SecretHive.Application.Ports;
using SecretHive.Application.Secrets;
using SecretHive.Domain.Entities;

namespace SecretHive.Web.Security;

/// <summary>
/// A job signing in with a token its own platform gave it: a CI run's identity token, or an application's
/// client-credentials token from an identity provider. Nothing is stored anywhere for it; the token is signed by an
/// issuer a super admin trusts for this, names an audience that is this server, lives for minutes, and says which
/// repository or application is asking.
///
/// What it may do comes from groups, as for people: the values of the provider's groups claim (for a CI system,
/// typically the repository) are matched to the provider's group links, and those groups hold roles in vaults. A
/// token that matches no link is a valid sign-in that sees nothing.
/// </summary>
public sealed class ProviderTokenHandler(IOptionsMonitor<AuthenticationSchemeOptions> options, ILoggerFactory logger, UrlEncoder encoder)
    : AuthenticationHandler<AuthenticationSchemeOptions>(options, logger, encoder)
{
    public const string SchemeName = "ProviderToken";
    public const string GroupClaim = "sh:group";
    public const string ProviderClaim = "sh:provider";

    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        var header = Request.Headers.Authorization.ToString();
        if (!header.StartsWith("Bearer ", StringComparison.Ordinal) || !IExternalTokenValidator.LooksLikeJwt(header["Bearer ".Length..].Trim()))
        {
            return AuthenticateResult.NoResult();
        }

        var address = Context.Connection.RemoteIpAddress is { } remote ? (remote.IsIPv4MappedToIPv6 ? remote.MapToIPv4() : remote).ToString() : null;
        var check = await Context.RequestServices.GetRequiredService<IExternalTokenValidator>().ValidateAsync(header["Bearer ".Length..].Trim(), Context.RequestAborted);
        if (check.Identity is not { } identity)
        {
            // Why, in a few words, and never anything of the token. A signed token is never somebody's password,
            // so a refused one is always worth a row.
            await Context.RequestServices.GetRequiredService<AuditWriter>().RecordAsync(
                "token.refused",
                new Caller(check.ProviderSlug is null ? "access token" : $"access token from {check.ProviderSlug}", address),
                check.Reason,
                AuditSeverity.Security,
                cancellationToken: Context.RequestAborted);
            return AuthenticateResult.Fail("That token is not accepted.");
        }

        var claimed = identity.Groups.ToHashSet(StringComparer.OrdinalIgnoreCase);
        var links = await Context.RequestServices.GetRequiredService<IAccessStore>().ProviderLinksForProviderAsync(identity.ProviderKey, Context.RequestAborted);
        var claims = new List<Claim>
        {
            // The provider's name in front: what a token calls itself is the issuer's word, not an account here.
            new(ClaimTypes.Name, $"{identity.ProviderSlug}:{identity.Caller}"),
            new(ProviderClaim, identity.ProviderKey.ToString(CultureInfo.InvariantCulture)),
        };
        claims.AddRange(links.Where(link => claimed.Contains(link.ProviderGroup)).Select(link => link.GroupKey).Distinct().Select(group => new Claim(GroupClaim, group.ToString(CultureInfo.InvariantCulture))));
        return AuthenticateResult.Success(new AuthenticationTicket(new ClaimsPrincipal(new ClaimsIdentity(claims, SchemeName)), SchemeName));
    }
}
