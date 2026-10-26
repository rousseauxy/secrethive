using System.Text.RegularExpressions;
using SecretHive.Application.Ports;
using SecretHive.Application.Secrets;
using SecretHive.Domain;
using SecretHive.Domain.Entities;

namespace SecretHive.Application.Accounts;

/// <summary>What an administrator fills in for a provider. <see cref="ClientSecret"/> empty keeps the stored one.</summary>
public sealed record ProviderSettings(
    string DisplayName,
    string Slug,
    string Authority,
    string ClientId,
    string? ClientSecret = null,
    string Scopes = OidcProvider.DefaultScopes,
    string UserNameClaim = OidcProvider.DefaultUserNameClaim,
    string GroupsClaim = "",
    bool Enabled = true,
    bool CreateAccounts = false,
    string AllowedEmailDomains = "",
    int Ordinal = 0,
    bool AcceptApiTokens = false,
    string ApiAudiences = "",
    string ApiRequiredClaims = "");

public sealed record ProviderGroupLink(int Key, int GroupKey, int ProviderKey, string ProviderName, string ProviderGroup);

/// <summary>
/// Sign-in providers: OpenID Connect issuers people may sign in with, kept in the database and read at each sign-in,
/// so adding or changing one needs no restart. Managed by super admins only: a provider decides who can get an
/// account, which is more than managing the accounts that exist. Its client secret is stored encrypted and never
/// comes back out through this service.
/// </summary>
public sealed partial class ProviderService(IOidcProviderStore providers, IAccessStore access, ISecretProtector secrets, AuditWriter audit, TimeProvider clock)
{
    public async Task<IReadOnlyList<OidcProvider>> ListAsync(Caller caller, CancellationToken cancellationToken = default)
    {
        RequireSuperAdmin(caller);
        return await providers.ListAsync(cancellationToken);
    }

    /// <summary>Whether a usable client secret is stored: false when none was entered, or the key that protected it is gone.</summary>
    public bool HasSecret(OidcProvider provider)
    {
        ArgumentNullException.ThrowIfNull(provider);
        return secrets.Unprotect(provider.ProtectedClientSecret) is not null;
    }

    public async Task<int> CreateAsync(ProviderSettings settings, Caller caller, CancellationToken cancellationToken = default)
    {
        RequireSuperAdmin(caller);
        ArgumentNullException.ThrowIfNull(settings);
        Validate(settings);
        if (settings.Enabled && string.IsNullOrWhiteSpace(settings.ClientSecret))
        {
            throw new DomainException("provider.invalid", "Enter the client secret, or leave the provider switched off until you have it.");
        }

        var now = clock.GetUtcNow().UtcDateTime;
        var provider = new OidcProvider { Slug = "", DisplayName = "", Authority = "", ClientId = "", CreatedUtc = now };
        Apply(settings, provider, now);
        if (!await providers.AddAsync(provider, cancellationToken))
        {
            throw new DomainException("provider.exists", $"A provider with the slug '{provider.Slug}' already exists.");
        }

        await audit.RecordAsync("provider.created", caller, Describe(provider), AuditSeverity.Notice, cancellationToken: cancellationToken);
        return (await providers.FindBySlugAsync(provider.Slug, cancellationToken))!.Key;
    }

    public async Task UpdateAsync(int key, ProviderSettings settings, Caller caller, CancellationToken cancellationToken = default)
    {
        RequireSuperAdmin(caller);
        ArgumentNullException.ThrowIfNull(settings);
        var provider = await providers.FindAsync(key, cancellationToken) ?? throw new DomainException("provider.not_found", "That provider does not exist.");
        Validate(settings);
        if (settings.Enabled && string.IsNullOrWhiteSpace(settings.ClientSecret) && !HasSecret(provider))
        {
            throw new DomainException("provider.invalid", "Enter the client secret to switch sign-ins on.");
        }

        var was = provider.Slug;
        Apply(settings, provider, clock.GetUtcNow().UtcDateTime);
        if (!await providers.UpdateAsync(provider, cancellationToken))
        {
            throw new DomainException("provider.exists", $"A provider with the slug '{provider.Slug}' already exists.");
        }

        // Whether the secret was replaced is on record. The secret is not, and neither is its length.
        await audit.RecordAsync("provider.updated", caller, $"{Describe(provider)} was={was} secret={(string.IsNullOrWhiteSpace(settings.ClientSecret) ? "kept" : "replaced")}", AuditSeverity.Notice, cancellationToken: cancellationToken);
    }

    /// <summary>
    /// Removes the provider, every account's connection to it, its group links and the memberships it gave. Accounts
    /// stay; one that only ever signed in through this provider has no way in until an administrator sets a password.
    /// </summary>
    public async Task DeleteAsync(int key, Caller caller, CancellationToken cancellationToken = default)
    {
        RequireSuperAdmin(caller);
        var provider = await providers.FindAsync(key, cancellationToken) ?? throw new DomainException("provider.not_found", "That provider does not exist.");
        await providers.DeleteAsync(key, cancellationToken);
        await audit.RecordAsync("provider.deleted", caller, provider.Slug, AuditSeverity.Notice, cancellationToken: cancellationToken);
    }

    /// <summary>Every link between a group at a provider and a group here, for the groups page.</summary>
    public async Task<IReadOnlyList<ProviderGroupLink>> ListLinksAsync(Caller caller, CancellationToken cancellationToken = default)
    {
        RequireAdmin(caller);
        var result = new List<ProviderGroupLink>();
        foreach (var provider in await providers.ListAsync(cancellationToken))
        {
            result.AddRange((await access.ProviderLinksForProviderAsync(provider.Key, cancellationToken))
                .Select(link => new ProviderGroupLink(link.Key, link.GroupKey, link.ProviderKey, provider.DisplayName, link.ProviderGroup)));
        }

        return result;
    }

    /// <summary>The providers a group can be linked to: their names, nothing about how they are set up.</summary>
    public async Task<IReadOnlyList<(int Key, string Name, bool SendsGroups)>> ListNamesAsync(Caller caller, CancellationToken cancellationToken = default)
    {
        RequireAdmin(caller);
        return [.. (await providers.ListAsync(cancellationToken)).Select(provider => (provider.Key, provider.DisplayName, provider.GroupsClaim.Length > 0))];
    }

    /// <summary>
    /// From then on, whoever signs in through that provider while in that group there is a member of the group here,
    /// and holds every role the group has. That is why it is written down as more than a quiet event.
    /// </summary>
    public async Task LinkGroupAsync(int groupKey, int providerKey, string providerGroup, Caller caller, CancellationToken cancellationToken = default)
    {
        RequireAdmin(caller);
        var name = (providerGroup ?? "").Trim();
        if (name.Length is 0 or > 256)
        {
            throw new DomainException("provider.invalid", "Enter the name of the group as the provider sends it.");
        }

        var group = await access.FindGroupAsync(groupKey, cancellationToken) ?? throw new DomainException("group.not_found", "That group does not exist.");
        var provider = await providers.FindAsync(providerKey, cancellationToken) ?? throw new DomainException("provider.not_found", "That provider does not exist.");
        if (!await access.AddProviderLinkAsync(new GroupProviderLink { GroupKey = groupKey, ProviderKey = providerKey, ProviderGroup = name }, cancellationToken))
        {
            throw new DomainException("provider.link.exists", "That group is already linked.");
        }

        await audit.RecordAsync("group.provider.linked", caller, $"{group.Name} <- {provider.Slug}:{name}", AuditSeverity.Notice, cancellationToken: cancellationToken);
    }

    public async Task UnlinkGroupAsync(int groupKey, int linkKey, Caller caller, CancellationToken cancellationToken = default)
    {
        RequireAdmin(caller);
        var group = await access.FindGroupAsync(groupKey, cancellationToken) ?? throw new DomainException("group.not_found", "That group does not exist.");
        var link = (await access.ProviderLinksAsync(groupKey, cancellationToken)).FirstOrDefault(candidate => candidate.Key == linkKey);
        if (link is not null && await access.RemoveProviderLinkAsync(groupKey, linkKey, cancellationToken))
        {
            await audit.RecordAsync("group.provider.unlinked", caller, $"{group.Name} <- {link.ProviderGroup}", cancellationToken: cancellationToken);
        }
    }

    private static void Validate(ProviderSettings settings)
    {
        if (settings.DisplayName.Trim().Length is 0 or > 64)
        {
            throw new DomainException("provider.invalid", "Enter a name for the button, at most 64 characters.");
        }

        if (!SlugPattern().IsMatch(settings.Slug.Trim()))
        {
            throw new DomainException("provider.invalid", "The slug is lower-case letters, digits and dashes, at most 32.");
        }

        // Plain http only on this machine, which is the rule the sign-in handler applies to the provider's metadata:
        // refused here, rather than saved and found broken at the first sign-in.
        if (settings.Authority.Trim().Length > 512
            || !Uri.TryCreate(settings.Authority.Trim(), UriKind.Absolute, out var authority)
            || !(authority.Scheme == "https" || (authority.Scheme == "http" && authority.IsLoopback)))
        {
            throw new DomainException("provider.invalid", "The issuer must be an absolute https:// URL.");
        }

        // Somebody has to be able to use it: people signing in, or jobs with tokens. An issuer trusted only for
        // tokens (a CI system) has no client here at all.
        if (!settings.Enabled && !settings.AcceptApiTokens && settings.ClientId.Trim().Length == 0)
        {
            throw new DomainException("provider.invalid", "Enter the client id, or accept API tokens from this issuer.");
        }

        if (settings.ClientId.Trim().Length > 256 || (settings.Enabled && settings.ClientId.Trim().Length == 0))
        {
            throw new DomainException("provider.invalid", "Enter the client id: people cannot sign in without one.");
        }

        if (settings.AcceptApiTokens && OidcProvider.ParseAudiences(settings.ApiAudiences).Count == 0)
        {
            throw new DomainException("provider.invalid", "Enter the audience tokens must be for. Without one, a token this issuer signs for any application would do.");
        }

        if (OidcProvider.ParseRequiredClaims(settings.ApiRequiredClaims) is not { } required || required.Keys.Any(name => !ClaimPattern().IsMatch(name)))
        {
            throw new DomainException("provider.invalid", "Required claims are one name=value per line, such as ref=refs/heads/main; a value may end in * (ref=refs/tags/docker-*), and only there.");
        }

        if (settings.ApiAudiences.Length > 1024 || settings.ApiRequiredClaims.Length > 1024)
        {
            throw new DomainException("provider.invalid", "The audiences or the required claims are too long.");
        }

        if (settings.ClientSecret is { Length: > 1024 })
        {
            throw new DomainException("provider.invalid", "The client secret is too long.");
        }

        if (OidcProvider.ParseEmailDomains(settings.AllowedEmailDomains).Any(domain => !DomainPattern().IsMatch(domain)))
        {
            throw new DomainException("provider.invalid", "Allowed email domains are host names such as example.org, one per line.");
        }

        if (!ClaimPattern().IsMatch(settings.UserNameClaim.Trim()) || (settings.GroupsClaim.Trim().Length > 0 && !ClaimPattern().IsMatch(settings.GroupsClaim.Trim())))
        {
            throw new DomainException("provider.invalid", "Claim names are letters, digits and . _ : / -.");
        }

        if (settings.Scopes.Length > 512)
        {
            throw new DomainException("provider.invalid", "The scopes are too long.");
        }
    }

    /// <summary>Copies the settings onto a provider. The secret is replaced only when one was typed.</summary>
    private void Apply(ProviderSettings settings, OidcProvider provider, DateTime utcNow)
    {
        provider.DisplayName = settings.DisplayName.Trim();
        provider.Slug = settings.Slug.Trim();
        provider.Authority = settings.Authority.Trim().TrimEnd('/');
        provider.ClientId = settings.ClientId.Trim();
        if (!string.IsNullOrWhiteSpace(settings.ClientSecret))
        {
            provider.ProtectedClientSecret = secrets.Protect(settings.ClientSecret.Trim());
        }

        provider.Scopes = string.Join(' ', settings.Scopes.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries));
        provider.UserNameClaim = settings.UserNameClaim.Trim();
        provider.GroupsClaim = settings.GroupsClaim.Trim();
        provider.Enabled = settings.Enabled;
        provider.CreateAccounts = settings.CreateAccounts;
        provider.AllowedEmailDomains = string.Join('\n', OidcProvider.ParseEmailDomains(settings.AllowedEmailDomains));
        provider.AcceptApiTokens = settings.AcceptApiTokens;
        provider.ApiAudiences = string.Join('\n', OidcProvider.ParseAudiences(settings.ApiAudiences));
        provider.ApiRequiredClaims = string.Join('\n', settings.ApiRequiredClaims.Split(['\n', '\r'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries));
        provider.Ordinal = settings.Ordinal;
        provider.UpdatedUtc = utcNow;
    }

    private static string Describe(OidcProvider provider) =>
        $"{provider.Slug} authority={provider.Authority} enabled={provider.Enabled} createAccounts={provider.CreateAccounts} apiTokens={provider.AcceptApiTokens}{(provider.AcceptApiTokens ? " audiences=" + provider.ApiAudiences.Replace('\n', ',') : "")}";

    private static void RequireSuperAdmin(Caller caller)
    {
        if (!(caller.Unrestricted || (caller.Role == UserRole.SuperAdmin && caller.KeyId is null)))
        {
            throw new DomainException("access.denied", "Only a super admin manages sign-in providers.");
        }
    }

    private static void RequireAdmin(Caller caller)
    {
        if (!caller.IsInstanceAdmin)
        {
            throw new DomainException("access.denied", "Only an administrator links groups.");
        }
    }

    [GeneratedRegex("^[a-z0-9][a-z0-9-]{0,31}$", RegexOptions.CultureInvariant)]
    private static partial Regex SlugPattern();

    [GeneratedRegex(@"^[A-Za-z0-9._:/-]{1,64}$", RegexOptions.CultureInvariant)]
    private static partial Regex ClaimPattern();

    [GeneratedRegex(@"^(?=.{1,253}$)[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$", RegexOptions.CultureInvariant)]
    private static partial Regex DomainPattern();
}
