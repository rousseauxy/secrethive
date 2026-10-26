using SecretHive.Domain.Entities;

namespace SecretHive.Application.Ports;

/// <summary>Groups, their members, and who holds which role in which vault.</summary>
public interface IAccessStore
{
    /// <summary>Every assignment that applies to an account: its own, and those of every group it is in.</summary>
    Task<IReadOnlyList<VaultAssignment>> ListAssignmentsForUserAsync(int userKey, CancellationToken cancellationToken);

    /// <summary>The assignments of a set of groups, for a caller that is groups and no account.</summary>
    Task<IReadOnlyList<VaultAssignment>> ListAssignmentsForGroupsAsync(IReadOnlyCollection<int> groupKeys, CancellationToken cancellationToken);

    Task<IReadOnlyList<VaultAssignment>> ListAssignmentsOfVaultAsync(Guid vaultId, CancellationToken cancellationToken);

    /// <summary>Gives a role, replacing whatever role that account or group held in that vault.</summary>
    Task SetAssignmentAsync(VaultAssignment assignment, CancellationToken cancellationToken);

    /// <summary>False when there was nothing to remove.</summary>
    Task<bool> RemoveAssignmentAsync(Guid vaultId, int? userKey, int? groupKey, CancellationToken cancellationToken);

    /// <summary>Every folder assignment that applies to an account: its own, and those of every group it is in.</summary>
    Task<IReadOnlyList<FolderAssignment>> ListFolderAssignmentsForUserAsync(int userKey, CancellationToken cancellationToken);

    /// <summary>The folder assignments of a set of groups, for a caller that is groups and no account.</summary>
    Task<IReadOnlyList<FolderAssignment>> ListFolderAssignmentsForGroupsAsync(IReadOnlyCollection<int> groupKeys, CancellationToken cancellationToken);

    /// <summary>Every folder assignment there is: few, and needed whole to say who a vault inherits.</summary>
    Task<IReadOnlyList<FolderAssignment>> ListFolderAssignmentsAsync(CancellationToken cancellationToken);

    /// <summary>Gives a role on a folder, replacing whatever role that account or group held on it.</summary>
    Task SetFolderAssignmentAsync(FolderAssignment assignment, CancellationToken cancellationToken);

    /// <summary>False when there was nothing to remove.</summary>
    Task<bool> RemoveFolderAssignmentAsync(Guid folderId, int? userKey, int? groupKey, CancellationToken cancellationToken);

    Task<IReadOnlyList<Group>> ListGroupsAsync(CancellationToken cancellationToken);

    Task<Group?> FindGroupAsync(int key, CancellationToken cancellationToken);

    /// <summary>False when the name is taken.</summary>
    Task<bool> AddGroupAsync(Group group, CancellationToken cancellationToken);

    /// <summary>The group with its members and every role it held.</summary>
    Task<bool> DeleteGroupAsync(int key, CancellationToken cancellationToken);

    Task<IReadOnlyList<GroupMember>> ListMembersAsync(int groupKey, CancellationToken cancellationToken);

    /// <summary>False when that account already is a member.</summary>
    Task<bool> AddMemberAsync(GroupMember member, CancellationToken cancellationToken);

    Task<bool> RemoveMemberAsync(int groupKey, int userKey, CancellationToken cancellationToken);

    /// <summary>The provider groups linked to one group here.</summary>
    Task<IReadOnlyList<GroupProviderLink>> ProviderLinksAsync(int groupKey, CancellationToken cancellationToken);

    /// <summary>Every link to groups of one provider, for refreshing memberships at a sign-in there.</summary>
    Task<IReadOnlyList<GroupProviderLink>> ProviderLinksForProviderAsync(int providerKey, CancellationToken cancellationToken);

    /// <summary>False when the same link exists or the group or provider does not.</summary>
    Task<bool> AddProviderLinkAsync(GroupProviderLink link, CancellationToken cancellationToken);

    Task<bool> RemoveProviderLinkAsync(int groupKey, int linkKey, CancellationToken cancellationToken);

    /// <summary>
    /// Makes the memberships this provider gave the account exactly <paramref name="groupKeys"/>: adds the missing
    /// ones, removes its own rows for groups no longer listed, and never touches a membership an administrator added.
    /// </summary>
    Task SyncProviderMembershipsAsync(int userKey, int providerKey, IReadOnlySet<int> groupKeys, CancellationToken cancellationToken);

    Task<IReadOnlyList<NetworkGroup>> ListNetworkGroupsAsync(CancellationToken cancellationToken);

    Task<NetworkGroup?> FindNetworkGroupAsync(int key, CancellationToken cancellationToken);

    /// <summary>False when the name is taken.</summary>
    Task<bool> AddNetworkGroupAsync(NetworkGroup group, CancellationToken cancellationToken);

    Task UpdateNetworkGroupAsync(NetworkGroup group, CancellationToken cancellationToken);

    /// <summary>False when something still lists it: a group in use is not deleted from under what relies on it.</summary>
    Task<bool> DeleteNetworkGroupAsync(int key, CancellationToken cancellationToken);

    /// <summary>Every line that lists a group, to say how far a change to it reaches.</summary>
    Task<IReadOnlyList<AllowedNetwork>> ListUsesOfNetworkGroupAsync(int groupKey, CancellationToken cancellationToken);

    Task<IReadOnlyList<AllowedNetwork>> ListAllowedNetworksAsync(Guid? vaultId, int? apiKeyKey, CancellationToken cancellationToken);

    /// <summary>False when the same line is already there.</summary>
    Task<bool> AddAllowedNetworkAsync(AllowedNetwork line, CancellationToken cancellationToken);

    Task<bool> RemoveAllowedNetworkAsync(int key, Guid? vaultId, int? apiKeyKey, CancellationToken cancellationToken);

    /// <summary>
    /// The ranges a vault or a key may be used from, groups resolved. Empty means it is not limited.
    /// </summary>
    Task<IReadOnlyList<string>> ResolveAllowedRangesAsync(Guid? vaultId, int? apiKeyKey, CancellationToken cancellationToken);
}
