using Microsoft.EntityFrameworkCore;
using SecretHive.Application.Accounts;
using SecretHive.Domain.Entities;

namespace SecretHive.Infrastructure.Persistence;

public sealed class EfKeyStore(SecretHiveDbContext db) : IKeyStore
{
    public Task<ApiKey?> FindAsync(int key, CancellationToken cancellationToken) =>
        db.ApiKeys.AsNoTracking().FirstOrDefaultAsync(item => item.Key == key, cancellationToken);

    public Task<ApiKey?> FindByPrefixAsync(string prefix, CancellationToken cancellationToken) =>
        db.ApiKeys.AsNoTracking().FirstOrDefaultAsync(item => item.Prefix == prefix, cancellationToken);

    public async Task<IReadOnlyList<ApiKey>> ListForUserAsync(int userKey, CancellationToken cancellationToken) =>
        await db.ApiKeys.AsNoTracking().Where(item => item.UserKey == userKey).ToListAsync(cancellationToken);

    public async Task AddAsync(ApiKey key, CancellationToken cancellationToken)
    {
        db.ApiKeys.Add(key);
        await db.SaveChangesAsync(cancellationToken);
        db.Entry(key).State = EntityState.Detached;
    }

    public Task RevokeAsync(int key, DateTime atUtc, CancellationToken cancellationToken) =>
        db.ApiKeys.Where(item => item.Key == key && item.RevokedUtc == null)
            .ExecuteUpdateAsync(set => set.SetProperty(item => item.RevokedUtc, atUtc), cancellationToken);

    public Task SetMaxRoleAsync(int key, VaultRole? maxRole, CancellationToken cancellationToken) =>
        db.ApiKeys.Where(item => item.Key == key)
            .ExecuteUpdateAsync(set => set.SetProperty(item => item.MaxRole, maxRole), cancellationToken);

    public Task TouchAsync(int key, DateTime atUtc, string? address, CancellationToken cancellationToken) =>
        db.ApiKeys.Where(item => item.Key == key)
            .ExecuteUpdateAsync(set => set.SetProperty(item => item.LastUsedUtc, atUtc).SetProperty(item => item.LastUsedAddress, address), cancellationToken);
}
