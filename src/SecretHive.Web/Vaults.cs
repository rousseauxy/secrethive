using Microsoft.AspNetCore.Components;
using SecretHive.Application.Accounts;
using SecretHive.Application.Ports;
using SecretHive.Application.Secrets;
using SecretHive.Domain;

namespace SecretHive.Web;

/// <summary>
/// How the pages reach the use cases. A page lives as long as its browser tab, and a database context must not:
/// each call here runs in a scope of its own, as a request to the API would, so a page never shows something only
/// because it was still in memory. The pages do nothing the API cannot do; both call the same use cases.
/// </summary>
/// <remarks>
/// A page is a circuit, not a request: the sign-in cookie is checked on every HTTP request and never on a circuit's
/// messages. So the account is checked here instead, before every call, against what it is now: disabled, or its
/// stamp moved (a new password, another role), ends the page's work and sends the browser to the sign-in form.
/// </remarks>
public sealed class Vaults(IServiceScopeFactory scopes, NavigationManager? navigation = null)
{
    /// <summary>Who is at the keyboard. Set once by the page's root, from the session the page was opened with.</summary>
    public Caller Caller { get; set; } = new("unknown", Via: "ui");

    /// <summary>The account's security stamp as it was in the cookie: a change since means the session has ended.</summary>
    public string? Stamp { get; set; }

    /// <summary>The same person for the account rules; null when the session is not an account.</summary>
    public AccountActor? Actor { get; set; }

    public bool IsAdmin { get; set; }

    public bool IsSuperAdmin { get; set; }

    /// <summary>The antiforgery field for the sign-out form, made where there still was a request.</summary>
    public string? FormTokenName { get; set; }

    public string? FormToken { get; set; }

    /// <summary>Raised when a page changed which vaults there are or where they sit, so the list beside it follows.</summary>
    public event Action? VaultsChanged;

    public void ChangedVaults() => VaultsChanged?.Invoke();

    public async Task<T> With<TService, T>(Func<TService, Task<T>> act)
        where TService : notnull
    {
        await using var scope = scopes.CreateAsyncScope();
        await RequireLiveSessionAsync(scope.ServiceProvider);
        return await act(scope.ServiceProvider.GetRequiredService<TService>());
    }

    /// <summary>
    /// The account behind this page, as it is now. Gone, disabled or changed since the sign-in: the browser goes
    /// back to the sign-in form, and the call that asked does not happen.
    /// </summary>
    private async Task RequireLiveSessionAsync(IServiceProvider services)
    {
        if (Caller.UserKey is not { } key)
        {
            return;
        }

        var user = await services.GetRequiredService<IUserStore>().FindAsync(key, CancellationToken.None);
        if (user is null || user.IsDisabled || (Stamp is not null && user.SecurityStamp != Stamp))
        {
            navigation?.NavigateTo("/login", forceLoad: true);
            throw new DomainException("session.ended", "This session has ended: the account was changed or disabled. Sign in again.");
        }
    }

    public Task<T> Run<T>(Func<SecretService, Task<T>> act) => With(act);

    public Task Run(Func<SecretService, Task> act) => Run(async service =>
    {
        await act(service);
        return true;
    });

    /// <summary>Runs something a person asked for and returns what went wrong, in words, or null when nothing did.</summary>
    public async Task<string?> Try(Func<SecretService, Task> act)
    {
        try
        {
            await Run(act);
            return null;
        }
        catch (DomainException e)
        {
            return e.Message;
        }
    }

    /// <summary>Writes an audit row for something a page did that is not about a secret.</summary>
    public Task Audit(string code, string? detail = null, Domain.Entities.AuditSeverity severity = Domain.Entities.AuditSeverity.Info) =>
        With<AuditWriter, bool>(async audit =>
        {
            await audit.RecordAsync(code, Caller, detail, severity);
            return true;
        });
}
