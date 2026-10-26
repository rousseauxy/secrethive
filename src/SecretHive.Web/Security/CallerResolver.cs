using Microsoft.AspNetCore.Authentication.Cookies;
using SecretHive.Api;
using SecretHive.Application.Secrets;
using SecretHive.Domain.Entities;

namespace SecretHive.Web.Security;

/// <summary>
/// Turns a request into the caller the use cases ask about: who, from where, through what, and with which
/// instance role. One place, so the pages and the API cannot come to different answers.
/// </summary>
public sealed class CallerResolver : ICallerResolver
{
    public Caller Resolve(HttpContext http)
    {
        var address = http.Connection.RemoteIpAddress is { } remote ? (remote.IsIPv4MappedToIPv6 ? remote.MapToIPv4() : remote).ToString() : null;
        // How it arrived is how it signed in: a session cookie is the pages, anything else is the API. Not a header,
        // which any caller could set to make its rows look like someone at a keyboard.
        var via = http.User.Identity?.AuthenticationType == CookieAuthenticationDefaults.AuthenticationScheme ? "ui" : "api";
        var name = http.User.Identity?.Name ?? "unknown";

        // The bootstrap token is the one credential that is nobody in particular and may do everything.
        if (http.User.Identity?.AuthenticationType == BootstrapAdminHandler.SchemeName)
        {
            return new Caller(name, address, via, Unrestricted: true);
        }

        // A key acts as its owner, inside the key's own limits, and never as an administrator, except the key of a service
        // identity a super admin made an admin: that one acts as an admin, never as a super admin.
        if (http.User.Identity?.AuthenticationType == ApiKeyHandler.SchemeName
            && int.TryParse(http.User.FindFirst(ApiKeyHandler.UserClaim)?.Value, System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out var owner)
            && int.TryParse(http.User.FindFirst(ApiKeyHandler.KeyClaim)?.Value, System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out var keyId))
        {
            return new Caller(
                name,
                address,
                "api",
                owner,
                http.User.HasClaim(ApiKeyHandler.AdminServiceClaim, "true") ? UserRole.Admin : UserRole.User,
                KeyId: keyId,
                KeyOfAdminService: http.User.HasClaim(ApiKeyHandler.AdminServiceClaim, "true"),
                OnlyVault: Guid.TryParseExact(http.User.FindFirst(ApiKeyHandler.VaultClaim)?.Value, "N", out var vault) ? vault : null,
                MaxRole: Enum.TryParse<VaultRole>(http.User.FindFirst(ApiKeyHandler.MaxRoleClaim)?.Value, out var max) ? max : null);
        }

        // A job with a token from its platform: no account, never an administrator, and exactly the groups it was matched to.
        if (http.User.Identity?.AuthenticationType == ProviderTokenHandler.SchemeName)
        {
            return new Caller(
                name,
                address,
                "api",
                Groups: [.. http.User.FindAll(ProviderTokenHandler.GroupClaim).Select(claim => int.Parse(claim.Value, System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture))]);
        }

        var actor = Accounts.Actor(http.User);
        return new Caller(name, address, via, actor?.Key, actor?.Role ?? UserRole.User);
    }
}
