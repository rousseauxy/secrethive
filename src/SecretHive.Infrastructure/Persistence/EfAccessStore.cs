using Microsoft.EntityFrameworkCore;
using SecretHive.Application.Ports;
using SecretHive.Domain.Entities;

namespace SecretHive.Infrastructure.Persistence;

public sealed class EfAccessStore(SecretHiveDbContext db) : IAccessStore
{
    public async Task<IReadOnlyList<VaultAssignment>> ListAssignmentsForUserAsync(int userKey, CancellationToken cancellationToken)
    {
        var groups = db.GroupMembers.Where(member => member.UserKey == userKey).Select(member => (int?)member.GroupKey);
        return await db.VaultAssignments.AsNoTracking()
            .Where(assignment => assignment.UserKey == userKey || groups.Contains(assignment.GroupKey))
            .ToListAsync(cancellationToken);
    }

    public async Task<IReadOnlyList<VaultAssignment>> ListAssignmentsForGroupsAsync(IReadOnlyCollection<int> groupKeys, CancellationToken cancellationToken)
    {
        var keys = groupKeys.Select(key => (int?)key).ToList();
        return await db.VaultAssignments.AsNoTracking().Where(assignment => keys.Contains(assignment.GroupKey)).ToListAsync(cancellationToken);
    }

    public async Task<IReadOnlyList<VaultAssignment>> ListAssignmentsOfVaultAsync(Guid vaultId, CancellationToken cancellationToken) =>
        await db.VaultAssignments.AsNoTracking().Where(assignment => assignment.VaultId == vaultId).OrderBy(assignment => assignment.Key).ToListAsync(cancellationToken);

    public async Task SetAssignmentAsync(VaultAssignment assignment, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(assignment);
        await RemoveAssignmentAsync(assignment.VaultId, assignment.UserKey, assignment.GroupKey, cancellationToken);
        db.VaultAssignments.Add(assignment);
        await db.SaveChangesAsync(cancellationToken);
        db.Entry(assignment).State = EntityState.Detached;
    }

    public async Task<bool> RemoveAssignmentAsync(Guid vaultId, int? userKey, int? groupKey, CancellationToken cancellationToken) =>
        await db.VaultAssignments
            .Where(assignment => assignment.VaultId == vaultId && assignment.UserKey == userKey && assignment.GroupKey == groupKey)
            .ExecuteDeleteAsync(cancellationToken) > 0;

    public async Task<IReadOnlyList<FolderAssignment>> ListFolderAssignmentsForUserAsync(int userKey, CancellationToken cancellationToken)
    {
        var groups = db.GroupMembers.Where(member => member.UserKey == userKey).Select(member => (int?)member.GroupKey);
        return await db.FolderAssignments.AsNoTracking()
            .Where(assignment => assignment.UserKey == userKey || groups.Contains(assignment.GroupKey))
            .ToListAsync(cancellationToken);
    }

    public async Task<IReadOnlyList<FolderAssignment>> ListFolderAssignmentsForGroupsAsync(IReadOnlyCollection<int> groupKeys, CancellationToken cancellationToken)
    {
        var keys = groupKeys.Select(key => (int?)key).ToList();
        return await db.FolderAssignments.AsNoTracking().Where(assignment => keys.Contains(assignment.GroupKey)).ToListAsync(cancellationToken);
    }

    public async Task<IReadOnlyList<FolderAssignment>> ListFolderAssignmentsAsync(CancellationToken cancellationToken) =>
        await db.FolderAssignments.AsNoTracking().OrderBy(assignment => assignment.Key).ToListAsync(cancellationToken);

    public async Task SetFolderAssignmentAsync(FolderAssignment assignment, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(assignment);
        await RemoveFolderAssignmentAsync(assignment.FolderId, assignment.UserKey, assignment.GroupKey, cancellationToken);
        db.FolderAssignments.Add(assignment);
        await db.SaveChangesAsync(cancellationToken);
        db.Entry(assignment).State = EntityState.Detached;
    }

    public async Task<bool> RemoveFolderAssignmentAsync(Guid folderId, int? userKey, int? groupKey, CancellationToken cancellationToken) =>
        await db.FolderAssignments
            .Where(assignment => assignment.FolderId == folderId && assignment.UserKey == userKey && assignment.GroupKey == groupKey)
            .ExecuteDeleteAsync(cancellationToken) > 0;

    public async Task<IReadOnlyList<Group>> ListGroupsAsync(CancellationToken cancellationToken) =>
        await db.Groups.AsNoTracking().OrderBy(group => group.NameLower).ToListAsync(cancellationToken);

    public Task<Group?> FindGroupAsync(int key, CancellationToken cancellationToken) =>
        db.Groups.AsNoTracking().FirstOrDefaultAsync(group => group.Key == key, cancellationToken);

    public async Task<bool> AddGroupAsync(Group group, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(group);
        if (await db.Groups.AnyAsync(existing => existing.NameLower == group.NameLower, cancellationToken))
        {
            return false;
        }

        db.Groups.Add(group);
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
            db.Entry(group).State = EntityState.Detached;
        }
    }

    public async Task<bool> DeleteGroupAsync(int key, CancellationToken cancellationToken)
    {
        await using var transaction = await db.Database.BeginTransactionAsync(cancellationToken);
        await db.VaultAssignments.Where(assignment => assignment.GroupKey == key).ExecuteDeleteAsync(cancellationToken);
        await db.FolderAssignments.Where(assignment => assignment.GroupKey == key).ExecuteDeleteAsync(cancellationToken);
        await db.GroupMembers.Where(member => member.GroupKey == key).ExecuteDeleteAsync(cancellationToken);
        await db.GroupProviderLinks.Where(link => link.GroupKey == key).ExecuteDeleteAsync(cancellationToken);
        var deleted = await db.Groups.Where(group => group.Key == key).ExecuteDeleteAsync(cancellationToken) > 0;
        await transaction.CommitAsync(cancellationToken);
        return deleted;
    }

    public async Task<IReadOnlyList<GroupMember>> ListMembersAsync(int groupKey, CancellationToken cancellationToken) =>
        await db.GroupMembers.AsNoTracking().Where(member => member.GroupKey == groupKey).ToListAsync(cancellationToken);

    public async Task<bool> AddMemberAsync(GroupMember member, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(member);
        if (await db.GroupMembers.AnyAsync(existing => existing.GroupKey == member.GroupKey && existing.UserKey == member.UserKey, cancellationToken))
        {
            return false;
        }

        db.GroupMembers.Add(member);
        await db.SaveChangesAsync(cancellationToken);
        db.Entry(member).State = EntityState.Detached;
        return true;
    }

    public async Task<bool> RemoveMemberAsync(int groupKey, int userKey, CancellationToken cancellationToken) =>
        await db.GroupMembers.Where(member => member.GroupKey == groupKey && member.UserKey == userKey).ExecuteDeleteAsync(cancellationToken) > 0;

    public async Task<IReadOnlyList<GroupProviderLink>> ProviderLinksAsync(int groupKey, CancellationToken cancellationToken) =>
        await db.GroupProviderLinks.AsNoTracking().Where(link => link.GroupKey == groupKey).OrderBy(link => link.ProviderKey).ThenBy(link => link.ProviderGroup).ToListAsync(cancellationToken);

    public async Task<IReadOnlyList<GroupProviderLink>> ProviderLinksForProviderAsync(int providerKey, CancellationToken cancellationToken) =>
        await db.GroupProviderLinks.AsNoTracking().Where(link => link.ProviderKey == providerKey).ToListAsync(cancellationToken);

    public async Task<bool> AddProviderLinkAsync(GroupProviderLink link, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(link);
        if (!await db.Groups.AnyAsync(group => group.Key == link.GroupKey, cancellationToken)
            || !await db.OidcProviders.AnyAsync(provider => provider.Key == link.ProviderKey, cancellationToken)
            || await db.GroupProviderLinks.AnyAsync(existing => existing.GroupKey == link.GroupKey && existing.ProviderKey == link.ProviderKey && existing.ProviderGroup == link.ProviderGroup, cancellationToken))
        {
            return false;
        }

        db.GroupProviderLinks.Add(link);
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
            db.Entry(link).State = EntityState.Detached;
        }
    }

    /// <summary>
    /// The link goes; the memberships it made stay until that member's next sign-in with the provider, which removes
    /// them. Removing them here would need the provider's other links to tell which rows another link still justifies.
    /// </summary>
    public async Task<bool> RemoveProviderLinkAsync(int groupKey, int linkKey, CancellationToken cancellationToken) =>
        await db.GroupProviderLinks.Where(link => link.Key == linkKey && link.GroupKey == groupKey).ExecuteDeleteAsync(cancellationToken) > 0;

    public async Task<IReadOnlyList<NetworkGroup>> ListNetworkGroupsAsync(CancellationToken cancellationToken) =>
        await db.NetworkGroups.AsNoTracking().OrderBy(group => group.NameLower).ToListAsync(cancellationToken);

    public Task<NetworkGroup?> FindNetworkGroupAsync(int key, CancellationToken cancellationToken) =>
        db.NetworkGroups.AsNoTracking().FirstOrDefaultAsync(group => group.Key == key, cancellationToken);

    public async Task<bool> AddNetworkGroupAsync(NetworkGroup group, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(group);
        if (await db.NetworkGroups.AnyAsync(existing => existing.NameLower == group.NameLower, cancellationToken))
        {
            return false;
        }

        db.NetworkGroups.Add(group);
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
            db.Entry(group).State = EntityState.Detached;
        }
    }

    public async Task UpdateNetworkGroupAsync(NetworkGroup group, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(group);
        await db.NetworkGroups
            .Where(existing => existing.Key == group.Key)
            .ExecuteUpdateAsync(set => set.SetProperty(existing => existing.Ranges, group.Ranges).SetProperty(existing => existing.Description, group.Description), cancellationToken);
    }

    public async Task<bool> DeleteNetworkGroupAsync(int key, CancellationToken cancellationToken) =>
        !await db.AllowedNetworks.AnyAsync(line => line.GroupKey == key, cancellationToken)
        && await db.NetworkGroups.Where(group => group.Key == key).ExecuteDeleteAsync(cancellationToken) > 0;

    public async Task<IReadOnlyList<AllowedNetwork>> ListUsesOfNetworkGroupAsync(int groupKey, CancellationToken cancellationToken) =>
        await db.AllowedNetworks.AsNoTracking().Where(line => line.GroupKey == groupKey).ToListAsync(cancellationToken);

    public async Task<IReadOnlyList<AllowedNetwork>> ListAllowedNetworksAsync(Guid? vaultId, int? apiKeyKey, CancellationToken cancellationToken) =>
        await db.AllowedNetworks.AsNoTracking().Where(line => line.VaultId == vaultId && line.ApiKeyKey == apiKeyKey).OrderBy(line => line.Key).ToListAsync(cancellationToken);

    public async Task<bool> AddAllowedNetworkAsync(AllowedNetwork line, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(line);
        if (await db.AllowedNetworks.AnyAsync(existing => existing.VaultId == line.VaultId && existing.ApiKeyKey == line.ApiKeyKey && existing.GroupKey == line.GroupKey && existing.Range == line.Range, cancellationToken))
        {
            return false;
        }

        db.AllowedNetworks.Add(line);
        await db.SaveChangesAsync(cancellationToken);
        db.Entry(line).State = EntityState.Detached;
        return true;
    }

    public async Task<bool> RemoveAllowedNetworkAsync(int key, Guid? vaultId, int? apiKeyKey, CancellationToken cancellationToken) =>
        await db.AllowedNetworks.Where(line => line.Key == key && line.VaultId == vaultId && line.ApiKeyKey == apiKeyKey).ExecuteDeleteAsync(cancellationToken) > 0;

    public async Task<IReadOnlyList<string>> ResolveAllowedRangesAsync(Guid? vaultId, int? apiKeyKey, CancellationToken cancellationToken)
    {
        var lines = await db.AllowedNetworks.AsNoTracking().Where(line => line.VaultId == vaultId && line.ApiKeyKey == apiKeyKey).ToListAsync(cancellationToken);
        if (lines.Count == 0)
        {
            return [];
        }

        var groupKeys = lines.Where(line => line.GroupKey is not null).Select(line => line.GroupKey!.Value).ToList();
        var groups = groupKeys.Count == 0 ? [] : await db.NetworkGroups.AsNoTracking().Where(group => groupKeys.Contains(group.Key)).ToListAsync(cancellationToken);

        // A listed group with no ranges allows nothing, and the list is still a limit: the caller gets a range no address is in.
        var ranges = lines.Where(line => line.Range is not null).Select(line => line.Range!).Concat(groups.SelectMany(group => group.RangeList())).Distinct(StringComparer.Ordinal).ToList();
        return ranges.Count == 0 ? ["255.255.255.255/32"] : ranges;
    }

    public async Task SyncProviderMembershipsAsync(int userKey, int providerKey, IReadOnlySet<int> groupKeys, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(groupKeys);
        var wanted = groupKeys.ToList();
        await db.GroupMembers
            .Where(member => member.UserKey == userKey && member.ProviderKey == providerKey && !wanted.Contains(member.GroupKey))
            .ExecuteDeleteAsync(cancellationToken);

        var present = await db.GroupMembers.AsNoTracking().Where(member => member.UserKey == userKey && wanted.Contains(member.GroupKey)).Select(member => member.GroupKey).ToListAsync(cancellationToken);
        var added = wanted.Except(present).Select(group => new GroupMember { GroupKey = group, UserKey = userKey, ProviderKey = providerKey, Source = "provider" }).ToList();
        if (added.Count == 0)
        {
            return;
        }

        db.GroupMembers.AddRange(added);
        try
        {
            await db.SaveChangesAsync(cancellationToken);
        }
        catch (DbUpdateException)
        {
            // Another sign-in added the same membership at the same moment; it is there either way.
        }
        finally
        {
            foreach (var member in added)
            {
                db.Entry(member).State = EntityState.Detached;
            }
        }
    }
}
