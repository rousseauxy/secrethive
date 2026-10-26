using System.Text;
using SecretHive.Application.Ports;
using SecretHive.Domain.Entities;

namespace SecretHive.Application.Accounts;

/// <summary>
/// Who a provider says the person is. <see cref="Groups"/> is null when the provider has no groups claim configured,
/// which leaves memberships alone; an empty list means "in no group" and removes the ones that provider gave.
/// </summary>
/// <param name="EmailVerified">The provider's <c>email_verified</c> claim; null when it sent none.</param>
public sealed record ExternalIdentity(string Subject, string? UserName, string? Email, string? DisplayName, IReadOnlyCollection<string>? Groups, bool? EmailVerified = null);

public enum ExternalSignInStatus
{
    SignedIn,

    /// <summary>No account had this identity, so one was made with the user role.</summary>
    Created,

    Disabled,

    /// <summary>
    /// No account had this identity, and the user name or email it brings belongs to an existing account. Nothing is made
    /// and nothing is joined: that person signs in to the existing account and connects the provider from its profile.
    /// </summary>
    MatchesExistingAccount,

    /// <summary>No account had this identity, and its email address is not a verified one in the provider's allowed domains.</summary>
    EmailNotAllowed,

    /// <summary>No account had this identity, and the provider does not make accounts: an admin makes one first.</summary>
    NoAccount,
}

public sealed record ExternalSignInResult(ExternalSignInStatus Status, User? User = null);

public enum LinkStatus
{
    Linked,
    AlreadyYours,
    BelongsToAnother,
}

public enum UnlinkStatus
{
    Removed,
    NotFound,

    /// <summary>The account has no password and no other provider: removing it would leave no way to sign in.</summary>
    LastWayToSignIn,
}

/// <summary>
/// Signing in through OpenID Connect providers. An identity is never matched to an existing
/// account by name or email: an unknown one makes a new account, and joining it to an existing one is done by that
/// account, signed in, from its profile page. An unknown identity whose user name or email an existing account already
/// has makes nothing: a second account for the same person is what that would be, which is worse than a refusal.
/// </summary>
public sealed class ExternalAccountService(IUserStore users, IExternalLoginStore logins, IAccessStore groups, TimeProvider time)
{
    private const int MaxUserNameLength = 64;

    /// <summary>The name when the provider sent nothing usable; it says nothing about who this is, so it matches nobody.</summary>
    private const string FallbackUserName = "user";

    public async Task<ExternalSignInResult> SignInAsync(OidcProvider provider, ExternalIdentity identity, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(provider);
        ArgumentNullException.ThrowIfNull(identity);
        var now = time.GetUtcNow().UtcDateTime;
        var login = await logins.FindAsync(provider.Key, identity.Subject, cancellationToken);
        if (login is not null && await users.FindAsync(login.UserKey, cancellationToken) is { } existing)
        {
            if (existing.IsDisabled)
            {
                return new ExternalSignInResult(ExternalSignInStatus.Disabled, existing);
            }

            await logins.TouchAsync(login.Key, identity.Email ?? "", now, cancellationToken);
            existing.LastSignInUtc = now;
            await users.UpdateAsync(existing, cancellationToken);
            await SyncGroupsAsync(existing.Key, provider, identity, cancellationToken);
            return new ExternalSignInResult(ExternalSignInStatus.SignedIn, existing);
        }

        // Checked before anything about existing accounts is looked at, so a refused identity learns nothing about them.
        if (!provider.AllowsEmail(identity.Email, identity.EmailVerified))
        {
            return new ExternalSignInResult(ExternalSignInStatus.EmailNotAllowed);
        }

        if (!provider.CreateAccounts)
        {
            return new ExternalSignInResult(ExternalSignInStatus.NoAccount);
        }

        if (await MatchesExistingAccountAsync(identity, cancellationToken))
        {
            return new ExternalSignInResult(ExternalSignInStatus.MatchesExistingAccount);
        }

        var user = await CreateAccountAsync(identity, now, cancellationToken);
        if (!await logins.AddAsync(NewLogin(user.Key, provider, identity, now), cancellationToken))
        {
            // The same identity signed in on another replica a moment ago and made its own account; keep that one.
            await users.DeleteAsync(user.Key, cancellationToken);
            return await SignInAsync(provider, identity, cancellationToken);
        }

        await SyncGroupsAsync(user.Key, provider, identity, cancellationToken);
        return new ExternalSignInResult(ExternalSignInStatus.Created, user);
    }

    /// <summary>Joins a provider identity to the signed-in account. Refused when it already belongs to someone else.</summary>
    public async Task<LinkStatus> LinkAsync(int userKey, OidcProvider provider, ExternalIdentity identity, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(provider);
        ArgumentNullException.ThrowIfNull(identity);
        if (await logins.FindAsync(provider.Key, identity.Subject, cancellationToken) is { } existing)
        {
            return existing.UserKey == userKey ? LinkStatus.AlreadyYours : LinkStatus.BelongsToAnother;
        }

        if (!await logins.AddAsync(NewLogin(userKey, provider, identity, time.GetUtcNow().UtcDateTime), cancellationToken))
        {
            return LinkStatus.BelongsToAnother;
        }

        await SyncGroupsAsync(userKey, provider, identity, cancellationToken);
        return LinkStatus.Linked;
    }

    public async Task<UnlinkStatus> UnlinkAsync(int userKey, int loginKey, CancellationToken cancellationToken)
    {
        var user = await users.FindAsync(userKey, cancellationToken);
        var links = await logins.ListForUserAsync(userKey, cancellationToken);
        if (user is null || !links.Any(l => l.Key == loginKey))
        {
            return UnlinkStatus.NotFound;
        }

        if (user.PasswordHash is null && links.Count == 1)
        {
            return UnlinkStatus.LastWayToSignIn;
        }

        return await logins.RemoveAsync(userKey, loginKey, cancellationToken) ? UnlinkStatus.Removed : UnlinkStatus.NotFound;
    }

    /// <summary>Whether the user name the identity would get, or its email address, is an existing account's.</summary>
    private async Task<bool> MatchesExistingAccountAsync(ExternalIdentity identity, CancellationToken cancellationToken)
    {
        if (!string.IsNullOrWhiteSpace(identity.Email) && await users.EmailInUseAsync(identity.Email, cancellationToken))
        {
            return true;
        }

        var name = UserNameFrom(identity);
        return name != FallbackUserName && await users.FindByUserNameAsync(name, cancellationToken) is not null;
    }

    /// <summary>
    /// A user name from what the provider sent - the configured claim, else the email's local part - reduced to the
    /// characters account names allow. Never empty.
    /// </summary>
    public static string UserNameFrom(ExternalIdentity identity)
    {
        ArgumentNullException.ThrowIfNull(identity);
        foreach (var candidate in new[] { identity.UserName, identity.Email?.Split('@')[0] })
        {
            var cleaned = Clean(candidate);
            if (cleaned.Length > 0)
            {
                return cleaned;
            }
        }

        return FallbackUserName;
    }

    private async Task<User> CreateAccountAsync(ExternalIdentity identity, DateTime now, CancellationToken cancellationToken)
    {
        var wanted = UserNameFrom(identity);
        for (var attempt = 1; ; attempt++)
        {
            var suffix = attempt == 1 ? "" : attempt <= 50 ? "-" + attempt : "-" + Guid.NewGuid().ToString("N")[..8];
            var name = wanted[..Math.Min(wanted.Length, MaxUserNameLength - suffix.Length)] + suffix;
            var user = new User
            {
                UserName = name,
                UserNameLower = name.ToLowerInvariant(),
                DisplayName = Truncate(identity.DisplayName, 128),
                Email = Truncate(identity.Email, 256),
                Role = UserRole.User,
                SecurityStamp = AccountService.NewStamp(),
                CreatedUtc = now,
                LastSignInUtc = now,
            };

            if (await users.AddAsync(user, cancellationToken))
            {
                return await users.FindByUserNameAsync(name, cancellationToken) ?? user;
            }
        }
    }

    /// <summary>
    /// The groups here that are linked to a group the identity is in, at this provider. Provider groups never grant a
    /// role; they only put the account in groups, and those hold roles in vaults.
    /// </summary>
    private async Task SyncGroupsAsync(int userKey, OidcProvider provider, ExternalIdentity identity, CancellationToken cancellationToken)
    {
        if (identity.Groups is null)
        {
            return;
        }

        var claimed = identity.Groups.ToHashSet(StringComparer.OrdinalIgnoreCase);
        var links = await groups.ProviderLinksForProviderAsync(provider.Key, cancellationToken);
        var groupKeys = links.Where(l => claimed.Contains(l.ProviderGroup)).Select(l => l.GroupKey).ToHashSet();
        await groups.SyncProviderMembershipsAsync(userKey, provider.Key, groupKeys, cancellationToken);
    }

    private static ExternalLogin NewLogin(int userKey, OidcProvider provider, ExternalIdentity identity, DateTime now) => new()
    {
        UserKey = userKey,
        ProviderKey = provider.Key,
        Subject = identity.Subject,
        Email = Truncate(identity.Email, 256),
        LinkedUtc = now,
        LastUsedUtc = now,
    };

    private static string Clean(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return "";
        }

        var builder = new StringBuilder();
        foreach (var c in value.Trim())
        {
            if (char.IsAsciiLetterOrDigit(c) || c is '.' or '-' or '_' or '@')
            {
                builder.Append(c);
            }
            else if (c is ' ' or '+')
            {
                builder.Append('.');
            }
        }

        // The account rule: starts with a letter or digit, at most 64 characters.
        var cleaned = builder.ToString().TrimStart('.', '-', '_', '@');
        return cleaned[..Math.Min(cleaned.Length, MaxUserNameLength)];
    }

    private static string Truncate(string? value, int max) =>
        string.IsNullOrEmpty(value) ? "" : value.Trim()[..Math.Min(value.Trim().Length, max)];
}
