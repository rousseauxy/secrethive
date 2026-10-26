using SecretHive.Domain;
using SecretHive.Domain.Entities;

namespace SecretHive.Application.Secrets;

/// <summary>A folder as a list shows it: where it is, and how much is directly in it.</summary>
public sealed record FolderSummary(string Name, string? Parent, string? Description, IReadOnlyList<string> Path, int Vaults, int Folders);

/// <summary>
/// Folders: a tree of vaults, the same for everyone, made and arranged by administrators. A role given on a folder
/// counts in every vault beneath it, at any depth, on top of what the vault gives itself; it only ever adds. It is
/// worked out at each check (<see cref="RightsAsync"/>) and never copied into the vaults, so moving a vault or a
/// folder changes who reaches it at once and leaves nothing behind. Because a move can widen access without anyone
/// touching a role, every move says who gains and who loses, and is a security event when anyone gains.
/// </summary>
public sealed partial class SecretService
{
    /// <summary>
    /// The folders a caller may know of: every one for an administrator, for anyone else those on the way to a vault
    /// they have a role in. Parents before children, by name.
    /// </summary>
    public async Task<IReadOnlyList<FolderSummary>> ListFoldersAsync(Caller caller, CancellationToken cancellationToken = default)
    {
        var folders = await store.ListFoldersAsync(cancellationToken);
        var vaults = await store.ListVaultsAsync(cancellationToken);
        var parents = folders.ToDictionary(folder => folder.Id, folder => folder.ParentId);
        var byId = folders.ToDictionary(folder => folder.Id);

        HashSet<Guid>? known = null;
        if (!caller.IsInstanceAdmin)
        {
            known = [];
            foreach (var vault in vaults)
            {
                if (await EffectiveRoleAsync(vault, caller, cancellationToken) is not null)
                {
                    known.UnionWith(Ancestors(vault.FolderId, parents));
                }
            }
        }

        return [.. folders
            .Where(folder => known is null || known.Contains(folder.Id))
            .Select(folder => new FolderSummary(
                folder.Name,
                folder.ParentId is { } parent && byId.TryGetValue(parent, out var above) ? above.Name : null,
                folder.Description,
                PathOf(folder.Id, parents, byId),
                vaults.Count(vault => vault.FolderId == folder.Id),
                folders.Count(child => child.ParentId == folder.Id)))
            .OrderBy(folder => string.Join('/', folder.Path), StringComparer.OrdinalIgnoreCase)];
    }

    public async Task CreateFolderAsync(string name, string? parent, string? description, Caller caller, CancellationToken cancellationToken = default)
    {
        RequireInstanceAdmin(caller, "create a folder");
        Naming.Folder(name);
        if (await store.FindFolderAsync(Key(name), cancellationToken) is not null)
        {
            throw new DomainException("folder.exists", $"A folder named '{name}' already exists.");
        }

        var above = parent is null ? null : await RequireFolderAsync(parent, cancellationToken);
        var folder = new Folder { Id = Guid.NewGuid(), Name = name, NameKey = Key(name), ParentId = above?.Id, Description = NullIfEmpty(description), CreatedUtc = Now() };
        store.Add(folder);
        store.Add(FolderAudit("folder.created", caller, folder, above is null ? null : $"in {above.Name}"));
        await store.SaveAsync(cancellationToken);
    }

    public async Task RenameFolderAsync(string name, string newName, Caller caller, CancellationToken cancellationToken = default)
    {
        RequireInstanceAdmin(caller, "rename a folder");
        var folder = await RequireFolderAsync(name, cancellationToken);
        Naming.Folder(newName);
        if (Key(newName) == folder.NameKey)
        {
            throw new DomainException("folder.rename.same", $"'{folder.Name}' already has that name.");
        }

        if (await store.FindFolderAsync(Key(newName), cancellationToken) is not null)
        {
            throw new DomainException("folder.exists", $"A folder named '{newName}' already exists.");
        }

        var old = folder.Name;
        (folder.Name, folder.NameKey) = (newName, Key(newName));
        store.Add(FolderAudit("folder.renamed", caller, folder, $"{old} -> {newName}"));
        await store.SaveAsync(cancellationToken);
    }

    public async Task SetFolderDescriptionAsync(string name, string? description, Caller caller, CancellationToken cancellationToken = default)
    {
        RequireInstanceAdmin(caller, "change a folder");
        var folder = await RequireFolderAsync(name, cancellationToken);
        folder.Description = NullIfEmpty(description);
        await store.SaveAsync(cancellationToken);
    }

    /// <summary>Removes a folder with nothing in it, and the roles given on it.</summary>
    public async Task DeleteFolderAsync(string name, Caller caller, CancellationToken cancellationToken = default)
    {
        RequireInstanceAdmin(caller, "delete a folder");
        var folder = await RequireFolderAsync(name, cancellationToken);
        var vaults = (await store.ListVaultsAsync(cancellationToken)).Count(vault => vault.FolderId == folder.Id);
        var folders = (await store.ListFoldersAsync(cancellationToken)).Count(child => child.ParentId == folder.Id);
        if (vaults > 0 || folders > 0)
        {
            throw new DomainException(
                "folder.not_empty",
                string.Create(System.Globalization.CultureInfo.InvariantCulture, $"'{folder.Name}' is not empty: {vaults} vault(s) and {folders} folder(s) in it. Move them out first."));
        }

        var roles = (await access.ListFolderAssignmentsAsync(cancellationToken)).Count(assignment => assignment.FolderId == folder.Id);
        store.Remove(folder);
        store.Add(FolderAudit("folder.deleted", caller, folder, roles > 0 ? $"with {roles} role(s) given on it" : null));
        await store.SaveAsync(cancellationToken);
    }

    /// <summary>Puts a folder in another one, or at the top with a null parent. Never into itself or below itself.</summary>
    public async Task MoveFolderAsync(string name, string? parent, Caller caller, CancellationToken cancellationToken = default)
    {
        RequireInstanceAdmin(caller, "move a folder");
        var folder = await RequireFolderAsync(name, cancellationToken);
        var above = parent is null ? null : await RequireFolderAsync(parent, cancellationToken);
        if (above?.Id == folder.ParentId)
        {
            throw new DomainException("folder.move.same", above is null ? $"'{folder.Name}' is at the top already." : $"'{folder.Name}' is in '{above.Name}' already.");
        }

        var parents = (await store.ListFoldersAsync(cancellationToken)).ToDictionary(item => item.Id, item => item.ParentId);
        if (above is not null && Ancestors(above.Id, parents).Contains(folder.Id))
        {
            throw new DomainException("folder.move.circle", $"'{folder.Name}' cannot go into '{above.Name}': that folder is inside it.");
        }

        // What is given on the folder and below it moves along; what changes is what it inherits from above.
        var change = await DescribeChangeAsync(folder.ParentId, above?.Id, cancellationToken);
        folder.ParentId = above?.Id;
        var audit = FolderAudit("folder.moved", caller, folder, Cap($"{(above is null ? "to the top" : $"into {above.Name}")}{change.Text}"));
        audit.Severity = change.Gains ? AuditSeverity.Security : AuditSeverity.Notice;
        store.Add(audit);
        await store.SaveAsync(cancellationToken);
    }

    /// <summary>Puts a vault in a folder, or at the top with a null folder.</summary>
    public async Task MoveVaultToFolderAsync(string vaultName, string? folderName, Caller caller, CancellationToken cancellationToken = default)
    {
        RequireInstanceAdmin(caller, "move a vault into a folder");
        var vault = await store.FindVaultAsync(Key(vaultName), cancellationToken)
            ?? throw new DomainException("vault.not_found", $"There is no vault '{vaultName}'.");
        var folder = folderName is null ? null : await RequireFolderAsync(folderName, cancellationToken);
        if (folder?.Id == vault.FolderId)
        {
            throw new DomainException("vault.folder.same", folder is null ? $"'{vault.Name}' is at the top already." : $"'{vault.Name}' is in '{folder.Name}' already.");
        }

        var change = await DescribeChangeAsync(vault.FolderId, folder?.Id, cancellationToken);
        vault.FolderId = folder?.Id;
        var audit = Audit("vault.folder.changed", caller, vault, detail: Cap($"{(folder is null ? "to the top" : $"into {folder.Name}")}{change.Text}"));
        audit.Severity = change.Gains ? AuditSeverity.Security : AuditSeverity.Notice;
        store.Add(audit);
        await store.SaveAsync(cancellationToken);
    }

    /// <summary>
    /// The roles given on a folder, and those it inherits from the folders above it (with <see cref="AccessEntry.From"/>
    /// naming the folder they are given on).
    /// </summary>
    public async Task<IReadOnlyList<AccessEntry>> ListFolderAccessAsync(string name, Caller caller, CancellationToken cancellationToken = default)
    {
        RequireInstanceAdmin(caller, "see who holds a role on a folder");
        var folder = await RequireFolderAsync(name, cancellationToken);
        var own = (await access.ListFolderAssignmentsAsync(cancellationToken)).Where(assignment => assignment.FolderId == folder.Id).ToList();
        return [.. await EntriesAsync(own.Select(assignment => (assignment.UserKey, assignment.GroupKey, assignment.Role, assignment.GrantedUtc, assignment.GrantedBy, (string?)null)), cancellationToken),
            .. await InheritedAsync(folder.ParentId, cancellationToken)];
    }

    /// <summary>
    /// Gives an account or a group a role on a folder, replacing the role it had there. Always a security event: it
    /// reaches every vault beneath the folder, now and later.
    /// </summary>
    public async Task AssignFolderAsync(string name, int? userKey, int? groupKey, VaultRole role, Caller caller, CancellationToken cancellationToken = default)
    {
        RequireInstanceAdmin(caller, "give a role on a folder");
        var folder = await RequireFolderAsync(name, cancellationToken);
        var who = await TargetNameAsync(userKey, groupKey, role, cancellationToken);
        await access.SetFolderAssignmentAsync(
            new FolderAssignment { FolderId = folder.Id, UserKey = userKey, GroupKey = groupKey, Role = role, GrantedUtc = Now(), GrantedBy = caller.Principal },
            cancellationToken);
        var reach = await VaultsBeneathAsync(folder.Id, cancellationToken);
        var audit = FolderAudit("folder.role.assigned", caller, folder, string.Create(System.Globalization.CultureInfo.InvariantCulture, $"{who} = {RoleName(role)}, reaching {reach} vault(s)"));
        audit.Severity = AuditSeverity.Security;
        store.Add(audit);
        await store.SaveAsync(cancellationToken);
    }

    public async Task UnassignFolderAsync(string name, int? userKey, int? groupKey, Caller caller, CancellationToken cancellationToken = default)
    {
        RequireInstanceAdmin(caller, "take a role on a folder away");
        var folder = await RequireFolderAsync(name, cancellationToken);
        if (!await access.RemoveFolderAssignmentAsync(folder.Id, userKey, groupKey, cancellationToken))
        {
            throw new DomainException("access.target.not_found", "That role is not given on this folder.");
        }

        var who = userKey is { } key
            ? $"user {(await users.FindAsync(key, cancellationToken))?.UserName ?? "(deleted)"}"
            : $"group {(await access.FindGroupAsync(groupKey ?? 0, cancellationToken))?.Name ?? "(deleted)"}";
        var audit = FolderAudit("folder.role.removed", caller, folder, who);
        audit.Severity = AuditSeverity.Notice;
        store.Add(audit);
        await store.SaveAsync(cancellationToken);
    }

    /// <summary>The roles a vault inherits from its folders, for its access list.</summary>
    private async Task<IReadOnlyList<AccessEntry>> InheritedAsync(Guid? folderId, CancellationToken cancellationToken)
    {
        if (folderId is null)
        {
            return [];
        }

        var folders = (await store.ListFoldersAsync(cancellationToken)).ToDictionary(folder => folder.Id);
        var parents = folders.ToDictionary(pair => pair.Key, pair => pair.Value.ParentId);
        var all = await access.ListFolderAssignmentsAsync(cancellationToken);
        var rows = new List<(int?, int?, VaultRole, DateTime, string, string?)>();
        foreach (var id in Ancestors(folderId, parents))
        {
            var from = folders.TryGetValue(id, out var folder) ? folder.Name : "(deleted folder)";
            rows.AddRange(all.Where(assignment => assignment.FolderId == id).Select(assignment => (assignment.UserKey, assignment.GroupKey, assignment.Role, assignment.GrantedUtc, assignment.GrantedBy, (string?)from)));
        }

        return await EntriesAsync(rows, cancellationToken);
    }

    private async Task<IReadOnlyList<AccessEntry>> EntriesAsync(IEnumerable<(int? UserKey, int? GroupKey, VaultRole Role, DateTime GrantedUtc, string GrantedBy, string? From)> rows, CancellationToken cancellationToken)
    {
        var userNames = (await users.ListAsync(cancellationToken)).ToDictionary(user => user.Key, user => user.UserName);
        var groupNames = (await access.ListGroupsAsync(cancellationToken)).ToDictionary(group => group.Key, group => group.Name);
        return [.. rows
            .Select(row => new AccessEntry(
                row.UserKey,
                row.GroupKey,
                row.UserKey is { } userKey ? userNames.GetValueOrDefault(userKey, "(deleted account)") : groupNames.GetValueOrDefault(row.GroupKey ?? 0, "(deleted group)"),
                row.Role,
                row.GrantedUtc,
                row.GrantedBy,
                row.From))
            .OrderByDescending(entry => VaultRoles.Place(entry.Role))
            .ThenBy(entry => entry.Name, StringComparer.OrdinalIgnoreCase)];
    }

    /// <summary>
    /// What moving something from beneath one folder to beneath another does to who reaches it, through the folders
    /// above: the accounts and groups that gain a right, and those that lose one. What is given on the thing itself
    /// and below it moves along and is left out.
    /// </summary>
    private async Task<(string Text, bool Gains)> DescribeChangeAsync(Guid? from, Guid? to, CancellationToken cancellationToken)
    {
        var parents = (await store.ListFoldersAsync(cancellationToken)).ToDictionary(folder => folder.Id, folder => folder.ParentId);
        var all = await access.ListFolderAssignmentsAsync(cancellationToken);
        Dictionary<(int?, int?), VaultRights> Through(Guid? start)
        {
            var held = new Dictionary<(int?, int?), VaultRights>();
            foreach (var id in Ancestors(start, parents))
            {
                foreach (var assignment in all.Where(assignment => assignment.FolderId == id))
                {
                    held[(assignment.UserKey, assignment.GroupKey)] = held.GetValueOrDefault((assignment.UserKey, assignment.GroupKey)) | assignment.Role.Rights();
                }
            }

            return held;
        }

        var before = Through(from);
        var after = Through(to);
        var userNames = (await users.ListAsync(cancellationToken)).ToDictionary(user => user.Key, user => user.UserName);
        var groupNames = (await access.ListGroupsAsync(cancellationToken)).ToDictionary(group => group.Key, group => group.Name);
        string Name((int? User, int? Group) who) => who.User is { } user ? $"user {userNames.GetValueOrDefault(user, "(deleted)")}" : $"group {groupNames.GetValueOrDefault(who.Group ?? 0, "(deleted)")}";

        var gains = after.Where(pair => (pair.Value & ~before.GetValueOrDefault(pair.Key)) != VaultRights.None)
            .Select(pair => $"{Name(pair.Key)} {RoleName(VaultRoles.Named(pair.Value))}").Order(StringComparer.OrdinalIgnoreCase).ToList();
        var losses = before.Where(pair => (pair.Value & ~after.GetValueOrDefault(pair.Key)) != VaultRights.None)
            .Select(pair => after.TryGetValue(pair.Key, out var left) ? $"{Name(pair.Key)} down to {RoleName(VaultRoles.Named(left))}" : Name(pair.Key))
            .Order(StringComparer.OrdinalIgnoreCase).ToList();
        var text = (gains.Count > 0 ? $"; gains: {string.Join(", ", gains)}" : "") + (losses.Count > 0 ? $"; loses: {string.Join(", ", losses)}" : "");
        return (text, gains.Count > 0);
    }

    /// <summary>An audit detail holds 2000 characters; a long list of who gains is cut and says so.</summary>
    private static string Cap(string text) => text.Length <= 1900 ? text : text[..1900] + " … (cut)";

    private async Task<int> VaultsBeneathAsync(Guid folderId, CancellationToken cancellationToken)
    {
        var parents = (await store.ListFoldersAsync(cancellationToken)).ToDictionary(folder => folder.Id, folder => folder.ParentId);
        return (await store.ListVaultsAsync(cancellationToken)).Count(vault => Ancestors(vault.FolderId, parents).Contains(folderId));
    }

    private async Task<string> TargetNameAsync(int? userKey, int? groupKey, VaultRole role, CancellationToken cancellationToken)
    {
        if ((userKey is null) == (groupKey is null))
        {
            throw new DomainException("access.target.invalid", "A role is given to one account or to one group.");
        }

        if (role.Rights() == VaultRights.None)
        {
            throw new DomainException("access.role.invalid", "That is not a role.");
        }

        var name = userKey is { } key ? (await users.FindAsync(key, cancellationToken))?.UserName : (await access.FindGroupAsync(groupKey!.Value, cancellationToken))?.Name;
        return name is null
            ? throw new DomainException("access.target.not_found", "That account or group does not exist.")
            : $"{(userKey is null ? "group" : "user")} {name}";
    }

    private async Task<Folder> RequireFolderAsync(string name, CancellationToken cancellationToken) =>
        await store.FindFolderAsync(Key(name ?? ""), cancellationToken)
            ?? throw new DomainException("folder.not_found", $"There is no folder '{name}'.");

    /// <summary>The names of the folders from the top down to this one.</summary>
    private static IReadOnlyList<string> PathOf(Guid? folderId, IReadOnlyDictionary<Guid, Guid?> parents, IReadOnlyDictionary<Guid, Folder> byId) =>
        [.. Ancestors(folderId, parents).Where(byId.ContainsKey).Select(id => byId[id].Name).Reverse()];

    /// <summary>A row of the trail about a folder: it names no vault, and says which folder in its detail.</summary>
    private AuditEvent FolderAudit(string code, Caller caller, Folder folder, string? detail) => new()
    {
        AtUtc = Now(),
        Code = code,
        Severity = AuditSeverity.Notice,
        Principal = caller.Principal,
        Address = caller.Address,
        Via = caller.Via,
        Detail = detail is null ? $"folder {folder.Name}" : $"folder {folder.Name}: {detail}",
    };
}
