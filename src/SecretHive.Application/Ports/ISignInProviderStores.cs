using SecretHive.Domain.Entities;

namespace SecretHive.Application.Ports;

public interface IOidcProviderStore
{
    /// <summary>Every provider, enabled or not, in button order.</summary>
    Task<IReadOnlyList<OidcProvider>> ListAsync(CancellationToken cancellationToken);

    Task<OidcProvider?> FindAsync(int key, CancellationToken cancellationToken);

    Task<OidcProvider?> FindBySlugAsync(string slug, CancellationToken cancellationToken);

    /// <summary>False when the slug is taken.</summary>
    Task<bool> AddAsync(OidcProvider provider, CancellationToken cancellationToken);

    /// <summary>Writes every field of a provider read earlier. False when the slug is taken or it no longer exists.</summary>
    Task<bool> UpdateAsync(OidcProvider provider, CancellationToken cancellationToken);

    /// <summary>The provider with its links, group mappings and the memberships it made.</summary>
    Task<bool> DeleteAsync(int key, CancellationToken cancellationToken);
}

public interface IExternalLoginStore
{
    Task<ExternalLogin?> FindAsync(int providerKey, string subject, CancellationToken cancellationToken);

    Task<IReadOnlyList<ExternalLogin>> ListForUserAsync(int userKey, CancellationToken cancellationToken);

    /// <summary>False when that provider identity is already joined to an account.</summary>
    Task<bool> AddAsync(ExternalLogin login, CancellationToken cancellationToken);

    Task TouchAsync(int loginKey, string email, DateTime utcNow, CancellationToken cancellationToken);

    /// <summary>Removes a link only when it belongs to <paramref name="userKey"/>.</summary>
    Task<bool> RemoveAsync(int userKey, int loginKey, CancellationToken cancellationToken);
}

/// <summary>Encrypts a secret for storage and back. An adapter, so the keys are the platform's data-protection keys.</summary>
public interface ISecretProtector
{
    string Protect(string secret);

    /// <summary>Null when the value cannot be read, for example after the keys were lost.</summary>
    string? Unprotect(string protectedSecret);
}
