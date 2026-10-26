using System.Globalization;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using SecretHive.Application.Accounts;
using SecretHive.Application.Ports;
using SecretHive.Domain.Entities;

namespace SecretHive.Web.Security;

/// <summary>
/// The sign-in cookie: what goes into it, and the check made on every request that it still describes a real,
/// enabled account. The check is what ends a session at once when a password or a role changes, or an account is
/// disabled, instead of when the cookie happens to expire.
/// </summary>
public static class Accounts
{
    public const string UserKeyClaim = "sh:user";
    public const string StampClaim = "sh:stamp";
    public const string AdminRole = "admin";
    public const string SuperAdminRole = "superadmin";

    /// <summary>Set on a request whose account has to choose a new password before anything else works.</summary>
    public const string MustChangePasswordItem = "sh:must-change-password";

    public const string PasswordPath = "/account/password";

    public static Task SignInUserAsync(HttpContext http, User user)
    {
        var claims = new List<Claim>
        {
            new(ClaimTypes.Name, user.UserName),
            new(UserKeyClaim, user.Key.ToString(CultureInfo.InvariantCulture)),
            new(StampClaim, user.SecurityStamp),
        };

        // Each role includes the ones before it, so a super admin also carries the admin role.
        if (user.Role >= UserRole.Admin)
        {
            claims.Add(new Claim(ClaimTypes.Role, AdminRole));
        }

        if (user.Role == UserRole.SuperAdmin)
        {
            claims.Add(new Claim(ClaimTypes.Role, SuperAdminRole));
        }

        var identity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
        return http.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, new ClaimsPrincipal(identity));
    }

    /// <summary>Who a signed-in principal is for the account rules, or null when it is not an account at all.</summary>
    public static AccountActor? Actor(ClaimsPrincipal? principal) =>
        int.TryParse(principal?.FindFirst(UserKeyClaim)?.Value, NumberStyles.None, CultureInfo.InvariantCulture, out var key)
            ? new AccountActor(key, principal!.IsInRole(SuperAdminRole) ? UserRole.SuperAdmin : principal.IsInRole(AdminRole) ? UserRole.Admin : UserRole.User)
            : null;

    public static async Task ValidateCookieAsync(CookieValidatePrincipalContext context)
    {
        var users = context.HttpContext.RequestServices.GetRequiredService<IUserStore>();
        var user = int.TryParse(context.Principal?.FindFirst(UserKeyClaim)?.Value, NumberStyles.None, CultureInfo.InvariantCulture, out var key)
            ? await users.FindAsync(key, context.HttpContext.RequestAborted)
            : null;
        if (user is null || user.IsDisabled || user.SecurityStamp != context.Principal!.FindFirst(StampClaim)?.Value)
        {
            context.RejectPrincipal();
            await context.HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            return;
        }

        if (user.MustChangePassword)
        {
            context.HttpContext.Items[MustChangePasswordItem] = true;
        }
    }

    /// <summary>
    /// An account that must choose a new password is sent to the page for it, whatever it asked for. Until then it
    /// can do nothing else: a first password is one somebody else knew.
    /// </summary>
    public static IApplicationBuilder UseForcedPasswordChange(this IApplicationBuilder app) => app.Use(async (context, next) =>
    {
        if (!context.Items.ContainsKey(MustChangePasswordItem))
        {
            await next();
            return;
        }

        // The API first, whatever the path looks like: a backup's name has an extension, and is not a stylesheet.
        var path = context.Request.Path;
        if (path.StartsWithSegments("/api"))
        {
            context.Response.StatusCode = StatusCodes.Status403Forbidden;
            return;
        }

        // The password page itself, signing out, the probe, and the files the page is made of.
        if (path.StartsWithSegments(PasswordPath)
            || path.StartsWithSegments("/logout")
            || path.StartsWithSegments("/health")
            || path.StartsWithSegments("/_framework")
            || Path.HasExtension(path.Value))
        {
            await next();
            return;
        }

        context.Response.Redirect(PasswordPath);
    });
}
