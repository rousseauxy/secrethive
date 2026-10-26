using SecretHive.Application.Ports;
using SecretHive.Domain.Entities;
using Microsoft.EntityFrameworkCore;

namespace SecretHive.Infrastructure.Persistence;

public sealed class EfOidcProviderStore(SecretHiveDbContext db) : IOidcProviderStore
{
    public async Task<IReadOnlyList<OidcProvider>> ListAsync(CancellationToken cancellationToken) =>
        await db.OidcProviders.AsNoTracking().OrderBy(p => p.Ordinal).ThenBy(p => p.Slug).ToListAsync(cancellationToken);

    public Task<OidcProvider?> FindAsync(int key, CancellationToken cancellationToken) =>
        db.OidcProviders.AsNoTracking().FirstOrDefaultAsync(p => p.Key == key, cancellationToken);

    public Task<OidcProvider?> FindBySlugAsync(string slug, CancellationToken cancellationToken)
    {
        var lower = (slug ?? "").ToLowerInvariant();
        return db.OidcProviders.AsNoTracking().FirstOrDefaultAsync(p => p.Slug == lower, cancellationToken);
    }

    public async Task<bool> AddAsync(OidcProvider provider, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(provider);
        if (await db.OidcProviders.AnyAsync(p => p.Slug == provider.Slug, cancellationToken))
        {
            return false;
        }

        db.OidcProviders.Add(provider);
        try
        {
            await db.SaveChangesAsync(cancellationToken);
            return true;
        }
        catch (DbUpdateException)
        {
            return false;
        }
        finally
        {
            db.Entry(provider).State = EntityState.Detached;
        }
    }

    public async Task<bool> UpdateAsync(OidcProvider provider, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(provider);
        if (await db.OidcProviders.AnyAsync(p => p.Slug == provider.Slug && p.Key != provider.Key, cancellationToken))
        {
            return false;
        }

        return await db.OidcProviders
            .Where(p => p.Key == provider.Key)
            .ExecuteUpdateAsync(
                s => s
                    .SetProperty(p => p.Slug, provider.Slug)
                    .SetProperty(p => p.DisplayName, provider.DisplayName)
                    .SetProperty(p => p.Authority, provider.Authority)
                    .SetProperty(p => p.ClientId, provider.ClientId)
                    .SetProperty(p => p.ProtectedClientSecret, provider.ProtectedClientSecret)
                    .SetProperty(p => p.Scopes, provider.Scopes)
                    .SetProperty(p => p.UserNameClaim, provider.UserNameClaim)
                    .SetProperty(p => p.GroupsClaim, provider.GroupsClaim)
                    .SetProperty(p => p.Enabled, provider.Enabled)
                    .SetProperty(p => p.CreateAccounts, provider.CreateAccounts)
                    .SetProperty(p => p.AllowedEmailDomains, provider.AllowedEmailDomains)
                    .SetProperty(p => p.AcceptApiTokens, provider.AcceptApiTokens)
                    .SetProperty(p => p.ApiAudiences, provider.ApiAudiences)
                    .SetProperty(p => p.ApiRequiredClaims, provider.ApiRequiredClaims)
                    .SetProperty(p => p.Ordinal, provider.Ordinal)
                    .SetProperty(p => p.UpdatedUtc, provider.UpdatedUtc),
                cancellationToken) > 0;
    }

    public async Task<bool> DeleteAsync(int key, CancellationToken cancellationToken)
    {
        await using var transaction = await db.Database.BeginTransactionAsync(cancellationToken);
        await db.GroupMembers.Where(m => m.ProviderKey == key).ExecuteDeleteAsync(cancellationToken);
        await db.GroupProviderLinks.Where(l => l.ProviderKey == key).ExecuteDeleteAsync(cancellationToken);
        await db.ExternalLogins.Where(l => l.ProviderKey == key).ExecuteDeleteAsync(cancellationToken);
        var deleted = await db.OidcProviders.Where(p => p.Key == key).ExecuteDeleteAsync(cancellationToken) > 0;
        await transaction.CommitAsync(cancellationToken);
        return deleted;
    }
}

public sealed class EfExternalLoginStore(SecretHiveDbContext db) : IExternalLoginStore
{
    public Task<ExternalLogin?> FindAsync(int providerKey, string subject, CancellationToken cancellationToken) =>
        db.ExternalLogins.AsNoTracking().FirstOrDefaultAsync(l => l.ProviderKey == providerKey && l.Subject == subject, cancellationToken);

    public async Task<IReadOnlyList<ExternalLogin>> ListForUserAsync(int userKey, CancellationToken cancellationToken) =>
        await db.ExternalLogins.AsNoTracking().Where(l => l.UserKey == userKey).OrderBy(l => l.ProviderKey).ToListAsync(cancellationToken);

    public async Task<bool> AddAsync(ExternalLogin login, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(login);
        if (await db.ExternalLogins.AnyAsync(l => l.ProviderKey == login.ProviderKey && l.Subject == login.Subject, cancellationToken))
        {
            return false;
        }

        db.ExternalLogins.Add(login);
        try
        {
            await db.SaveChangesAsync(cancellationToken);
            return true;
        }
        catch (DbUpdateException)
        {
            return false;
        }
        finally
        {
            db.Entry(login).State = EntityState.Detached;
        }
    }

    public Task TouchAsync(int loginKey, string email, DateTime utcNow, CancellationToken cancellationToken) =>
        db.ExternalLogins
            .Where(l => l.Key == loginKey)
            .ExecuteUpdateAsync(s => s.SetProperty(l => l.Email, email).SetProperty(l => l.LastUsedUtc, utcNow), cancellationToken);

    public async Task<bool> RemoveAsync(int userKey, int loginKey, CancellationToken cancellationToken) =>
        await db.ExternalLogins.Where(l => l.Key == loginKey && l.UserKey == userKey).ExecuteDeleteAsync(cancellationToken) > 0;
}
