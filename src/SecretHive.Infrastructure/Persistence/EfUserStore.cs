using SecretHive.Application.Ports;
using SecretHive.Domain.Entities;
using Microsoft.EntityFrameworkCore;

namespace SecretHive.Infrastructure.Persistence;

public sealed class EfUserStore(SecretHiveDbContext db) : IUserStore
{
    public Task<User?> FindAsync(int key, CancellationToken cancellationToken) =>
        db.Users.AsNoTracking().FirstOrDefaultAsync(u => u.Key == key, cancellationToken);

    public Task<User?> FindByUserNameAsync(string userName, CancellationToken cancellationToken)
    {
        var lower = userName.ToLowerInvariant();
        return db.Users.AsNoTracking().FirstOrDefaultAsync(u => u.UserNameLower == lower, cancellationToken);
    }

    public Task<bool> EmailInUseAsync(string email, CancellationToken cancellationToken)
    {
        var lower = email.Trim().ToLowerInvariant();

        // Runs as SQL LOWER() in the database, not as .NET string code: the culture rules below do not apply to it, and the
        // StringComparison overloads they suggest have no translation.
#pragma warning disable CA1304, CA1311, CA1862
        return db.Users.AnyAsync(u => u.Email != "" && u.Email.ToLower() == lower, cancellationToken);
#pragma warning restore CA1304, CA1311, CA1862
    }

    public async Task<IReadOnlyList<User>> ListAsync(CancellationToken cancellationToken) =>
        await db.Users.AsNoTracking().OrderBy(u => u.UserNameLower).ToListAsync(cancellationToken);

    public Task<bool> AnyAsync(CancellationToken cancellationToken) => db.Users.AnyAsync(cancellationToken);

    public Task<int> CountActiveSuperAdminsAsync(CancellationToken cancellationToken) =>
        db.Users.CountAsync(u => u.Role == UserRole.SuperAdmin && !u.IsDisabled, cancellationToken);

    public async Task<bool> AddAsync(User user, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(user);
        if (await db.Users.AnyAsync(u => u.UserNameLower == user.UserNameLower, cancellationToken))
        {
            return false;
        }

        db.Users.Add(user);
        try
        {
            await db.SaveChangesAsync(cancellationToken);
            return true;
        }
        catch (DbUpdateException)
        {
            // The same name added by another request or replica at the same moment.
            db.Entry(user).State = EntityState.Detached;
            return false;
        }
        finally
        {
            db.Entry(user).State = EntityState.Detached;
        }
    }

    public async Task<bool> UpdateAsync(User user, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(user);
        return await db.Users
            .Where(u => u.Key == user.Key)
            .ExecuteUpdateAsync(
                s => s
                    .SetProperty(u => u.DisplayName, user.DisplayName)
                    .SetProperty(u => u.Email, user.Email)
                    .SetProperty(u => u.PasswordHash, user.PasswordHash)
                    .SetProperty(u => u.Role, user.Role)
                    .SetProperty(u => u.IsDisabled, user.IsDisabled)
                    .SetProperty(u => u.IsService, user.IsService)
                    .SetProperty(u => u.MustChangePassword, user.MustChangePassword)
                    .SetProperty(u => u.SecurityStamp, user.SecurityStamp)
                    .SetProperty(u => u.FailedSignIns, user.FailedSignIns)
                    .SetProperty(u => u.LockedUntilUtc, user.LockedUntilUtc)
                    .SetProperty(u => u.LastSignInUtc, user.LastSignInUtc),
                cancellationToken) > 0;
    }

    /// <summary>
    /// Two statements, each atomic on both providers. Reading the count and writing back one more lost every attempt that
    /// overlapped: thirty wrong passwords sent at once left the count at one and the account open.
    /// </summary>
    public async Task<bool> RecordFailedSignInAsync(int key, int maxFailures, DateTime lockedUntilUtc, CancellationToken cancellationToken)
    {
        await db.Users
            .Where(u => u.Key == key)
            .ExecuteUpdateAsync(s => s.SetProperty(u => u.FailedSignIns, u => u.FailedSignIns + 1), cancellationToken);

        return await db.Users
            .Where(u => u.Key == key && u.FailedSignIns >= maxFailures)
            .ExecuteUpdateAsync(
                s => s
                    .SetProperty(u => u.LockedUntilUtc, lockedUntilUtc)
                    .SetProperty(u => u.FailedSignIns, 0),
                cancellationToken) > 0;
    }

    /// <summary>The account with its group memberships and every role it held.</summary>
    public async Task<bool> DeleteAsync(int key, CancellationToken cancellationToken)
    {
        await using var transaction = await db.Database.BeginTransactionAsync(cancellationToken);
        await db.ApiKeys.Where(k => k.UserKey == key).ExecuteDeleteAsync(cancellationToken);
        await db.VaultAssignments.Where(a => a.UserKey == key).ExecuteDeleteAsync(cancellationToken);
        await db.FolderAssignments.Where(a => a.UserKey == key).ExecuteDeleteAsync(cancellationToken);
        await db.Pins.Where(p => p.UserKey == key).ExecuteDeleteAsync(cancellationToken);
        await db.GroupMembers.Where(m => m.UserKey == key).ExecuteDeleteAsync(cancellationToken);
        var deleted = await db.Users.Where(u => u.Key == key).ExecuteDeleteAsync(cancellationToken) > 0;
        await transaction.CommitAsync(cancellationToken);
        return deleted;
    }
}
