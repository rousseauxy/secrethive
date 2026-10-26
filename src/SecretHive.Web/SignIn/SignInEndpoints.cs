using System.Security.Claims;
using System.Text.Json;
using SecretHive.Application.Accounts;
using SecretHive.Application.Ports;
using SecretHive.Domain.Entities;
using SecretHive.Application.Secrets;
using SecretHive.Web.Security;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Authentication;

namespace SecretHive.Web.SignIn;

/// <summary>
/// Sign-in and account linking through OpenID Connect providers. The provider's handler signs its answer in to the short
/// external cookie; <c>/account/external/complete</c> then decides whose account that is, and issues the real sign-in.
/// </summary>
public static class SignInEndpoints
{
    private const string ProviderItem = "secrethive:provider";
    private const string LinkItem = "secrethive:link";
    private const string ReturnItem = "secrethive:return";
    private const string CompletePath = "/account/external/complete";
    private const string ReturnPath = "/account/external/return";

    public static void MapExternalSignIn(this WebApplication app)
    {
        // A button on the sign-in page. A POST with the page's antiforgery token, so no other site can start a sign-in with
        // an identity of its choosing in this browser.
        app.MapPost("/account/external/{slug}", async (string slug, HttpContext http, IOidcProviderStore providers) =>
        {
            if (!await ValidAsync(http))
            {
                return Results.Redirect("/login?external=expired");
            }

            var provider = await providers.FindBySlugAsync(slug, http.RequestAborted);
            if (provider is not { Enabled: true })
            {
                return Results.Redirect("/login?external=unknown");
            }

            var form = await http.Request.ReadFormAsync(http.RequestAborted);
            return Challenge(provider, returnUrl: LocalOrRoot(form["returnUrl"].ToString()), linkTo: null);
        }).AllowAnonymous().DisableAntiforgery();

        // Connect a provider to the signed-in account, from its profile page.
        app.MapPost("/account/external/{slug}/link", async (string slug, HttpContext http, IOidcProviderStore providers) =>
        {
            var actor = Accounts.Actor(http.User);
            if (actor is null || !await ValidAsync(http))
            {
                return Results.Redirect("/account/profile?linked=expired");
            }

            var provider = await providers.FindBySlugAsync(slug, http.RequestAborted);
            return provider is not { Enabled: true }
                ? Results.Redirect("/account/profile?linked=unknown")
                : Challenge(provider, returnUrl: "/account/profile", linkTo: actor.Key);
        }).RequireAuthorization().DisableAntiforgery();

        // The provider's answer arrives as a redirect from another site, and a browser does not send this site's
        // session cookie along such a chain, nor after it. So the chain ends here, on a page of this site that asks for
        // the next one itself: from there on the session cookie travels again, and can stay strictly same-site.
        app.MapGet(ReturnPath, () => Results.Content(
            $"<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta http-equiv=\"refresh\" content=\"0;url={CompletePath}\"><title>Signing in</title></head><body><p><a href=\"{CompletePath}\">Continue</a></p></body></html>",
            "text/html; charset=utf-8")).AllowAnonymous();

        app.MapGet(CompletePath, CompleteAsync).AllowAnonymous();

        app.MapPost("/account/external/logins/{key:int}/remove", async (
            int key,
            HttpContext http,
            ExternalAccountService external,
            IExternalLoginStore logins,
            IOidcProviderStore providers,
            AuditWriter audit) =>
        {
            var actor = Accounts.Actor(http.User);
            if (actor is null || !await ValidAsync(http))
            {
                return Results.Redirect("/account/profile");
            }

            // Which provider, looked up before the link is gone.
            var login = (await logins.ListForUserAsync(actor.Key, http.RequestAborted)).FirstOrDefault(l => l.Key == key);
            var provider = login is null ? null : await providers.FindAsync(login.ProviderKey, http.RequestAborted);
            var outcome = await external.UnlinkAsync(actor.Key, key, http.RequestAborted);
            if (outcome == UnlinkStatus.Removed)
            {
                await audit.RecordAsync("auth.external.unlinked", CallerOf(http, http.User.Identity?.Name ?? ""), $"provider={provider?.Slug ?? "?"}{(string.IsNullOrEmpty(login?.Email) ? "" : " as=" + login.Email)}");
            }

            return Results.Redirect("/account/profile?unlinked=" + (outcome == UnlinkStatus.LastWayToSignIn ? "last" : "ok"));
        }).RequireAuthorization().DisableAntiforgery();
    }

    private static async Task<IResult> CompleteAsync(
        HttpContext http,
        IOidcProviderStore providers,
        ExternalAccountService external,
        AuditWriter audit)
    {
        var result = await http.AuthenticateAsync(OidcSchemes.ExternalCookie);
        await http.SignOutAsync(OidcSchemes.ExternalCookie);
        if (!result.Succeeded || result.Properties?.Items.TryGetValue(ProviderItem, out var slug) != true || slug is null)
        {
            return Results.Redirect("/login?external=failed");
        }

        var provider = await providers.FindBySlugAsync(slug, http.RequestAborted);
        var identity = provider is { Enabled: true } ? IdentityFrom(result.Principal!, provider) : null;
        if (provider is null || identity is null)
        {
            await audit.RecordAsync("auth.external.failed", CallerOf(http, slug), "no provider or no subject");
            return Results.Redirect("/login?external=failed");
        }

        if (result.Properties.Items.TryGetValue(LinkItem, out var link) && link is not null)
        {
            // Only for the account that asked: the sign-in cookie must still be that account's when the provider answers.
            var actor = Accounts.Actor(http.User);
            if (actor is null || actor.Key.ToString(System.Globalization.CultureInfo.InvariantCulture) != link)
            {
                return Results.Redirect("/login?external=failed");
            }

            var status = await external.LinkAsync(actor.Key, provider, identity, http.RequestAborted);
            await audit.RecordAsync("auth.external.linked", CallerOf(http, http.User.Identity?.Name ?? ""), $"provider={provider.Slug} status={status}");
            return Results.Redirect("/account/profile?linked=" + status switch
            {
                LinkStatus.Linked => "ok",
                LinkStatus.AlreadyYours => "already",
                _ => "taken",
            });
        }

        var outcome = await external.SignInAsync(provider, identity, http.RequestAborted);
        if (outcome.Status == ExternalSignInStatus.MatchesExistingAccount)
        {
            await audit.RecordAsync("auth.external.refused", CallerOf(http, identity.UserName ?? identity.Email ?? identity.Subject), $"provider={provider.Slug} reason=matches-existing-account");
            return Results.Redirect("/login?external=exists");
        }

        if (outcome.Status is ExternalSignInStatus.EmailNotAllowed or ExternalSignInStatus.NoAccount)
        {
            var reason = outcome.Status == ExternalSignInStatus.EmailNotAllowed ? "email-not-allowed" : "no-account";
            await audit.RecordAsync("auth.external.refused", CallerOf(http, identity.UserName ?? identity.Email ?? identity.Subject), $"provider={provider.Slug} reason={reason} email={identity.Email ?? "-"}");
            return Results.Redirect("/login?external=" + reason);
        }

        if (outcome.Status == ExternalSignInStatus.Disabled)
        {
            await audit.RecordAsync("auth.signin.disabled", CallerOf(http, outcome.User!.UserName), $"provider={provider.Slug}");
            return Results.Redirect("/login?external=disabled");
        }

        await Accounts.SignInUserAsync(http, outcome.User!);
        await audit.RecordAsync(
            outcome.Status == ExternalSignInStatus.Created ? "auth.external.created" : "auth.signin",
            CallerOf(http, outcome.User!.UserName),
            $"provider={provider.Slug}",
            outcome.Status == ExternalSignInStatus.Created ? Domain.Entities.AuditSeverity.Notice : Domain.Entities.AuditSeverity.Info);
        return Results.Redirect(result.Properties.Items.TryGetValue(ReturnItem, out var back) ? LocalOrRoot(back) : "/");
    }

    /// <summary>What the provider said, from the ID token and the user info answer together. Null without a subject.</summary>
    public static ExternalIdentity? IdentityFrom(ClaimsPrincipal principal, OidcProvider provider)
    {
        ArgumentNullException.ThrowIfNull(principal);
        ArgumentNullException.ThrowIfNull(provider);
        var subject = principal.FindFirst("sub")?.Value;
        if (string.IsNullOrEmpty(subject))
        {
            return null;
        }

        IReadOnlyCollection<string>? groups = null;
        if (!string.IsNullOrWhiteSpace(provider.GroupsClaim))
        {
            groups = principal.FindAll(provider.GroupsClaim).SelectMany(c => Values(c.Value)).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        }

        return new ExternalIdentity(
            subject,
            principal.FindFirst(provider.UserNameClaim)?.Value,
            principal.FindFirst("email")?.Value,
            principal.FindFirst("name")?.Value,
            groups,
            bool.TryParse(principal.FindFirst("email_verified")?.Value, out var verified) ? verified : null);
    }

    private static IResult Challenge(OidcProvider provider, string returnUrl, int? linkTo)
    {
        var properties = new AuthenticationProperties { RedirectUri = ReturnPath };
        properties.Items[ProviderItem] = provider.Slug;
        properties.Items[ReturnItem] = returnUrl;
        if (linkTo is not null)
        {
            properties.Items[LinkItem] = linkTo.Value.ToString(System.Globalization.CultureInfo.InvariantCulture);
        }

        return Results.Challenge(properties, [OidcSchemes.Name(provider.Slug)]);
    }

    /// <summary>A groups claim is one claim per group, or - from some user info answers - one claim holding a JSON array.</summary>
    private static IEnumerable<string> Values(string value)
    {
        if (value.StartsWith('['))
        {
            string[]? parsed = null;
            try
            {
                parsed = JsonSerializer.Deserialize<string[]>(value);
            }
            catch (JsonException)
            {
            }

            if (parsed is not null)
            {
                return parsed.Where(v => !string.IsNullOrWhiteSpace(v));
            }
        }

        return string.IsNullOrWhiteSpace(value) ? [] : [value];
    }

    private static Caller CallerOf(HttpContext http, string principal) =>
        new(principal is { Length: > 0 and <= 256 } ? principal : "unknown", http.Connection.RemoteIpAddress is { } remote ? (remote.IsIPv4MappedToIPv6 ? remote.MapToIPv4() : remote).ToString() : null, "ui");

    private static Task<bool> ValidAsync(HttpContext http) =>
        http.RequestServices.GetRequiredService<IAntiforgery>().IsRequestValidAsync(http);

    private static string LocalOrRoot(string? url) => ReturnUrls.LocalOr(url, "/");
}
