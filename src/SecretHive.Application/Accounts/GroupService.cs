using SecretHive.Application.Ports;
using SecretHive.Application.Secrets;
using SecretHive.Domain;
using SecretHive.Domain.Entities;

namespace SecretHive.Application.Accounts;

public sealed record GroupSummary(int Key, string Name, string Description, IReadOnlyList<(int UserKey, string UserName, string Source)> Members);

/// <summary>
/// Groups: named sets of accounts, so a role in a vault is given once to a team. Managed by administrators. A
/// group grants nothing by itself; what its members may do is what the group was given in each vault.
/// </summary>
public sealed class GroupService(IAccessStore access, IUserStore users, AuditWriter audit, TimeProvider clock)
{
    public async Task<IReadOnlyList<GroupSummary>> ListAsync(Caller caller, CancellationToken cancellationToken = default)
    {
        Require(caller);
        var names = (await users.ListAsync(cancellationToken)).ToDictionary(user => user.Key, user => user.UserName);
        var result = new List<GroupSummary>();
        foreach (var group in await access.ListGroupsAsync(cancellationToken))
        {
            var members = (await access.ListMembersAsync(group.Key, cancellationToken))
                .Where(member => names.ContainsKey(member.UserKey))
                .Select(member => (member.UserKey, names[member.UserKey], member.Source))
                .OrderBy(member => member.Item2, StringComparer.OrdinalIgnoreCase)
                .ToList();
            result.Add(new GroupSummary(group.Key, group.Name, group.Description, members));
        }

        return result;
    }

    public async Task CreateAsync(string name, string? description, Caller caller, CancellationToken cancellationToken = default)
    {
        Require(caller);
        Naming.Secret(name);
        var group = new Group { Name = name, NameLower = name.ToLowerInvariant(), Description = (description ?? "").Trim(), CreatedUtc = clock.GetUtcNow().UtcDateTime };
        if (!await access.AddGroupAsync(group, cancellationToken))
        {
            throw new DomainException("group.exists", $"A group named '{name}' already exists.");
        }

        await audit.RecordAsync("group.created", caller, name, cancellationToken: cancellationToken);
    }

    /// <summary>Deletes the group, and with it every role it held in every vault.</summary>
    public async Task DeleteAsync(int groupKey, Caller caller, CancellationToken cancellationToken = default)
    {
        Require(caller);
        var group = await access.FindGroupAsync(groupKey, cancellationToken) ?? throw new DomainException("group.not_found", "That group does not exist.");
        await access.DeleteGroupAsync(groupKey, cancellationToken);
        await audit.RecordAsync("group.deleted", caller, group.Name, AuditSeverity.Notice, cancellationToken: cancellationToken);
    }

    public async Task AddMemberAsync(int groupKey, int userKey, Caller caller, CancellationToken cancellationToken = default)
    {
        Require(caller);
        var group = await access.FindGroupAsync(groupKey, cancellationToken) ?? throw new DomainException("group.not_found", "That group does not exist.");
        var user = await users.FindAsync(userKey, cancellationToken) ?? throw new DomainException("user.not_found", "That account does not exist.");
        if (await access.AddMemberAsync(new GroupMember { GroupKey = groupKey, UserKey = userKey }, cancellationToken))
        {
            // Joining a group is how someone comes to hold every role the group has, so it is not a quiet event; an
            // administrator adding themselves, or a service identity whose keys they can make, is a security event.
            var toSelf = userKey == caller.UserKey || user.IsService;
            await audit.RecordAsync("group.member.added", caller, $"{group.Name} + {user.UserName}", toSelf ? AuditSeverity.Security : AuditSeverity.Notice, cancellationToken: cancellationToken);
        }
    }

    public async Task RemoveMemberAsync(int groupKey, int userKey, Caller caller, CancellationToken cancellationToken = default)
    {
        Require(caller);
        var group = await access.FindGroupAsync(groupKey, cancellationToken) ?? throw new DomainException("group.not_found", "That group does not exist.");
        var user = await users.FindAsync(userKey, cancellationToken);
        if (await access.RemoveMemberAsync(groupKey, userKey, cancellationToken))
        {
            await audit.RecordAsync("group.member.removed", caller, $"{group.Name} - {user?.UserName ?? "(deleted account)"}", cancellationToken: cancellationToken);
        }
    }

    private static void Require(Caller caller)
    {
        if (!caller.IsInstanceAdmin)
        {
            throw new DomainException("access.denied", "Only an administrator manages groups.");
        }
    }
}
