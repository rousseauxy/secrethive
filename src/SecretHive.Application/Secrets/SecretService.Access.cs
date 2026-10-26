using SecretHive.Domain;
using SecretHive.Domain.Entities;

namespace SecretHive.Application.Secrets;

/// <summary>
/// One line of an access list: an account or a group, and the role it holds there. <see cref="From"/> names the
/// folder a role is given on when it is inherited from there; it is changed on that folder, not here.
/// </summary>
public sealed record AccessEntry(int? UserKey, int? GroupKey, string Name, VaultRole Role, DateTime GrantedUtc, string GrantedBy, string? From = null);

/// <summary>
/// Who may do what. Every use case asks here before it touches anything, with the least role it needs; nothing
/// is decided in a page or an endpoint, so every way in applies the same rules.
/// </summary>
public sealed partial class SecretService
{
    // What this caller holds, read once per unit of work: in vaults, on folders, and where each folder is.
    private Dictionary<Guid, VaultRights>? _assigned;
    private Dictionary<Guid, VaultRights>? _folderAssigned;
    private Dictionary<Guid, Guid?>? _parents;
    private Caller? _assignedFor;

    /// <summary>
    /// The role a caller has in a vault, or null when the vault is none of their business. An instance
    /// administrator sees every vault as a Reader, because they hand out the roles; to read a value they need a role
    /// like anyone else, and giving themselves one is on record.
    /// </summary>
    private async Task<VaultRole?> EffectiveRoleAsync(Vault vault, Caller caller, CancellationToken cancellationToken) =>
        await RightsAsync(vault, caller, cancellationToken) is { } rights ? VaultRoles.Named(rights) : null;

    /// <summary>
    /// What a caller may do in a vault, or null when the vault is none of their business. Roles held through
    /// several assignments add up; a key takes away whatever its highest role does not include.
    /// </summary>
    private async Task<VaultRights?> RightsAsync(Vault vault, Caller caller, CancellationToken cancellationToken)
    {
        if (caller.Unrestricted)
        {
            return VaultRole.VaultAdmin.Rights();
        }

        if (_assigned is null || !ReferenceEquals(_assignedFor, caller))
        {
            _assigned = [];
            _assignedFor = caller;
            // An account holds its own roles and those of its groups. A job that signed in with a token from its
            // platform is no account: it holds what the groups it was matched to hold, and nothing else.
            var assignments = caller.UserKey is { } userKey ? await access.ListAssignmentsForUserAsync(userKey, cancellationToken)
                : caller.Groups is { Count: > 0 } groups ? await access.ListAssignmentsForGroupsAsync(groups, cancellationToken)
                : [];
            foreach (var assignment in assignments)
            {
                _assigned[assignment.VaultId] = _assigned.GetValueOrDefault(assignment.VaultId) | assignment.Role.Rights();
            }

            // The same for folders: a role on a folder counts in every vault beneath it.
            _folderAssigned = [];
            var onFolders = caller.UserKey is { } folderUser ? await access.ListFolderAssignmentsForUserAsync(folderUser, cancellationToken)
                : caller.Groups is { Count: > 0 } folderGroups ? await access.ListFolderAssignmentsForGroupsAsync(folderGroups, cancellationToken)
                : [];
            foreach (var assignment in onFolders)
            {
                _folderAssigned[assignment.FolderId] = _folderAssigned.GetValueOrDefault(assignment.FolderId) | assignment.Role.Rights();
            }

            _parents = _folderAssigned.Count == 0 ? [] : (await store.ListFoldersAsync(cancellationToken)).ToDictionary(folder => folder.Id, folder => folder.ParentId);
        }

        // What is given in the vault, and on each folder above it. A role nobody knows gives nothing, so the vault
        // stays out of sight.
        var given = _assigned.GetValueOrDefault(vault.Id);
        foreach (var folder in Ancestors(vault.FolderId, _parents!))
        {
            given |= _folderAssigned!.GetValueOrDefault(folder);
        }

        VaultRights? role = given != VaultRights.None ? given : null;
        role = role is null && caller.IsInstanceAdmin ? VaultRights.See : role;

        // A key acts as its owner and never as more: only in its one vault when it has one, and never above its cap.
        if (caller.OnlyVault is { } only && only != vault.Id)
        {
            return null;
        }

        return role is { } held && caller.MaxRole is { } cap ? held & (cap.Rights() | VaultRights.See) : role;
    }

    /// <summary>
    /// A folder and every folder above it, nearest first. A parent that is no folder ends the walk; so does a circle,
    /// which the service never makes but a hand-edited database could.
    /// </summary>
    private static IEnumerable<Guid> Ancestors(Guid? folderId, IReadOnlyDictionary<Guid, Guid?> parents)
    {
        var seen = new HashSet<Guid>();
        for (var current = folderId; current is { } id && seen.Add(id); current = parents.GetValueOrDefault(id))
        {
            yield return id;
            if (!parents.ContainsKey(id))
            {
                yield break;
            }
        }
    }

    /// <summary>
    /// The vault, if the caller holds at least this role in it. A vault the caller has no role in at all does not
    /// exist as far as they can tell; one where the role is too low is refused, and the refusal is on record.
    /// </summary>
    /// <remarks>
    /// With <paramref name="setting"/> the question is not a place on the ladder but the right to set a value,
    /// which a Secrets Writer has and a Secrets User has not.
    /// </remarks>
    private async Task<Vault> RequireVaultAsync(string name, Caller caller, VaultRole needed, CancellationToken cancellationToken, bool fromAnywhere = false, bool setting = false)
    {
        var vault = await store.FindVaultAsync(Key(name), cancellationToken);
        var role = vault is null ? null : await RightsAsync(vault, caller, cancellationToken);
        if (vault is null || role is null)
        {
            throw new DomainException("vault.not_found", $"There is no vault '{name}'.");
        }

        // After "does this vault exist for you" and before anything about its secrets: where the request comes from.
        if (!fromAnywhere)
        {
            await RequireNetworkAsync(vault, caller, cancellationToken);
        }

        var right = setting ? VaultRights.Set : VaultRoles.Needs(needed);
        if (!role.Value.HasFlag(right))
        {
            // A key held back by its own limit is said to be that: "has Secrets User" sends whoever reads it to the
            // role list, where the owner holds enough and nothing looks wrong.
            var takes = setting ? $"{RoleName(VaultRole.SecretsWriter)} or {RoleName(VaultRole.SecretsOfficer)}" : RoleName(needed);
            var has = RoleName(VaultRoles.Named(role.Value));
            var limited = await LimitedByKeyAsync(vault, caller, right, cancellationToken);
            var denied = Audit("access.denied", caller, vault, detail: limited is { } owner
                ? $"needs {takes}; the key is limited to {RoleName(caller.MaxRole!.Value)}, its owner holds {RoleName(owner)}"
                : $"needs {takes}, has {has}");
            denied.Severity = AuditSeverity.Notice;
            store.Add(denied);
            await store.SaveAsync(cancellationToken);
            throw new DomainException("access.denied", limited is { } holds
                ? $"That needs the role {takes} in '{vault.Name}'. This key is limited to {RoleName(caller.MaxRole!.Value)}; its owner holds {RoleName(holds)}. Raise the key's highest role, or lift it so the key follows its owner's role."
                : $"That needs the role {takes} in '{vault.Name}'; you have {has}.");
        }

        return vault;
    }

    /// <summary>
    /// The role the owner of a key holds in a vault, when that role would have been enough and only the key's own
    /// limit stands in the way. Null for every other caller, and for a key whose owner does not hold enough either.
    /// </summary>
    private async Task<VaultRole?> LimitedByKeyAsync(Vault vault, Caller caller, VaultRights needed, CancellationToken cancellationToken)
    {
        if (caller.KeyId is null || caller.MaxRole is null)
        {
            return null;
        }

        return await RightsAsync(vault, caller with { MaxRole = null }, cancellationToken) is { } owner && owner.HasFlag(needed) ? VaultRoles.Named(owner) : null;
    }

    private static void RequireInstanceAdmin(Caller caller, string what)
    {
        if (!caller.IsInstanceAdmin)
        {
            throw new DomainException("access.denied", $"Only an administrator can {what}.");
        }
    }

    /// <summary>The caller's role in a vault, for a page that wants to show only what can be done.</summary>
    public async Task<VaultRole?> RoleAsync(string vaultName, Caller caller, CancellationToken cancellationToken = default)
    {
        var vault = await store.FindVaultAsync(Key(vaultName), cancellationToken);
        return vault is null ? null : await EffectiveRoleAsync(vault, caller, cancellationToken);
    }

    /// <summary>
    /// Whether the caller may set a value here: a Secrets Writer, a Secrets Officer or more. A page asks this and
    /// not the role, because the right to set does not follow from a place on the ladder.
    /// </summary>
    public async Task<bool> CanSetAsync(string vaultName, Caller caller, CancellationToken cancellationToken = default) =>
        await store.FindVaultAsync(Key(vaultName), cancellationToken) is { } vault
        && await RightsAsync(vault, caller, cancellationToken) is { } rights
        && rights.HasFlag(VaultRights.Set);

    /// <summary>Whether the caller decides who has which role here: a Vault Admin of this vault, or an instance administrator.</summary>
    public async Task<bool> CanManageAccessAsync(string vaultName, Caller caller, CancellationToken cancellationToken = default) =>
        caller.IsInstanceAdmin || await RoleAsync(vaultName, caller, cancellationToken) == VaultRole.VaultAdmin;

    public async Task<IReadOnlyList<AccessEntry>> ListAccessAsync(string vaultName, Caller caller, CancellationToken cancellationToken = default)
    {
        var vault = await RequireAccessManagerAsync(vaultName, caller, cancellationToken);
        var own = await access.ListAssignmentsOfVaultAsync(vault.Id, cancellationToken);
        return [.. await EntriesAsync(own.Select(assignment => (assignment.UserKey, assignment.GroupKey, assignment.Role, assignment.GrantedUtc, assignment.GrantedBy, (string?)null)), cancellationToken),
            .. await InheritedAsync(vault.FolderId, cancellationToken)];
    }

    /// <summary>Gives an account or a group a role in a vault, replacing the role it had there.</summary>
    public async Task AssignAsync(string vaultName, int? userKey, int? groupKey, VaultRole role, Caller caller, CancellationToken cancellationToken = default)
    {
        var vault = await RequireAccessManagerAsync(vaultName, caller, cancellationToken);
        if ((userKey is null) == (groupKey is null))
        {
            throw new DomainException("access.target.invalid", "A role is given to one account or to one group.");
        }

        if (role.Rights() == VaultRights.None)
        {
            throw new DomainException("access.role.invalid", "That is not a role.");
        }

        var user = userKey is { } key ? await users.FindAsync(key, cancellationToken) : null;
        var name = userKey is not null ? user?.UserName : (await access.FindGroupAsync(groupKey!.Value, cancellationToken))?.Name;
        if (name is null)
        {
            throw new DomainException("access.target.not_found", "That account or group does not exist.");
        }

        await access.SetAssignmentAsync(
            new VaultAssignment { VaultId = vault.Id, UserKey = userKey, GroupKey = groupKey, Role = role, GrantedUtc = Now(), GrantedBy = caller.Principal },
            cancellationToken);

        // What must never pass quietly: a new Vault Admin, and every route by which the caller comes to read a
        // value themselves. A role to oneself; a reading role to a service identity, whose keys an administrator
        // can make; a reading role to a group the caller is in.
        var toSelf = userKey is not null && userKey == caller.UserKey;
        var toOwnMachine = user is { IsService: true };
        var toOwnGroup = groupKey is { } group && caller.UserKey is { } me && (await access.ListMembersAsync(group, cancellationToken)).Any(member => member.UserKey == me);
        var audit = Audit("vault.role.assigned", caller, vault, detail: $"{(userKey is null ? "group" : "user")} {name} = {RoleName(role)}");
        audit.Severity = role == VaultRole.VaultAdmin || toSelf || (role.Rights().HasFlag(VaultRights.Read) && (toOwnMachine || toOwnGroup)) ? AuditSeverity.Security : AuditSeverity.Notice;
        store.Add(audit);
        await store.SaveAsync(cancellationToken);
    }

    public async Task UnassignAsync(string vaultName, int? userKey, int? groupKey, Caller caller, CancellationToken cancellationToken = default)
    {
        var vault = await RequireAccessManagerAsync(vaultName, caller, cancellationToken);
        if (!await access.RemoveAssignmentAsync(vault.Id, userKey, groupKey, cancellationToken))
        {
            throw new DomainException("access.target.not_found", "That role is not assigned.");
        }

        var name = userKey is { } key
            ? (await users.FindAsync(key, cancellationToken))?.UserName
            : (await access.FindGroupAsync(groupKey ?? 0, cancellationToken))?.Name;
        var audit = Audit("vault.role.removed", caller, vault, detail: $"{(userKey is null ? "group" : "user")} {name ?? "(deleted)"}");
        audit.Severity = AuditSeverity.Notice;
        store.Add(audit);
        await store.SaveAsync(cancellationToken);
    }

    private async Task<Vault> RequireAccessManagerAsync(string vaultName, Caller caller, CancellationToken cancellationToken) =>
        caller.IsInstanceAdmin
            ? await RequireVaultAsync(vaultName, caller, VaultRole.Reader, cancellationToken, fromAnywhere: true)
            : await RequireVaultAsync(vaultName, caller, VaultRole.VaultAdmin, cancellationToken, fromAnywhere: true);

    /// <summary>The vaults a caller has any role in, by id.</summary>
    private async Task<HashSet<Guid>> VisibleVaultsAsync(Caller caller, CancellationToken cancellationToken)
    {
        var visible = new HashSet<Guid>();
        foreach (var vault in await store.ListVaultsAsync(cancellationToken))
        {
            if (await EffectiveRoleAsync(vault, caller, cancellationToken) is not null)
            {
                visible.Add(vault.Id);
            }
        }

        return visible;
    }

    /// <summary>The vaults a caller has a role in, with that role and the folders it is in, by name.</summary>
    public async Task<IReadOnlyList<VaultPlace>> ListMyVaultsAsync(Caller caller, CancellationToken cancellationToken = default)
    {
        var mine = new List<VaultPlace>();
        var folders = await store.ListFoldersAsync(cancellationToken);
        var parents = folders.ToDictionary(folder => folder.Id, folder => folder.ParentId);
        var byId = folders.ToDictionary(folder => folder.Id);
        foreach (var vault in await store.ListVaultsAsync(cancellationToken))
        {
            if (await EffectiveRoleAsync(vault, caller, cancellationToken) is { } role)
            {
                mine.Add(new VaultPlace(vault.Name, vault.Description, role, PathOf(vault.FolderId, parents, byId)));
            }
        }

        return [.. mine.OrderBy(vault => vault.Name, StringComparer.OrdinalIgnoreCase)];
    }

    public static string RoleName(VaultRole role) => role switch
    {
        VaultRole.Reader => "Reader",
        VaultRole.SecretsWriter => "Secrets Writer",
        VaultRole.SecretsUser => "Secrets User",
        VaultRole.SecretsOfficer => "Secrets Officer",
        _ => "Vault Admin",
    };
}
