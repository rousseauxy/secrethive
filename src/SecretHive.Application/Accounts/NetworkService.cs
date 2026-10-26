using System.Globalization;
using SecretHive.Application.Ports;
using SecretHive.Application.Secrets;
using SecretHive.Domain;
using SecretHive.Domain.Entities;

namespace SecretHive.Application.Accounts;

/// <summary>A network group with how far it reaches: the number of vaults and keys that list it.</summary>
public sealed record NetworkGroupSummary(int Key, string Name, string Description, IReadOnlyList<string> Ranges, int Vaults, int Keys);

/// <summary>One line of a vault's or a key's list of allowed networks: a group by name, or a literal range.</summary>
public sealed record NetworkLine(int Key, int? GroupKey, string Label, IReadOnlyList<string> Ranges);

/// <summary>
/// Network groups: named lists of address ranges, defined once. Managed by instance administrators and not by
/// Vault Admins, because editing a shared group changes vaults the editor may not administer. Every change says
/// what the ranges were, what they are, and how many vaults and keys it reaches.
/// </summary>
public sealed class NetworkService(IAccessStore access, AuditWriter audit, TimeProvider clock)
{
    public async Task<IReadOnlyList<NetworkGroupSummary>> ListAsync(Caller caller, CancellationToken cancellationToken = default)
    {
        Require(caller);
        var result = new List<NetworkGroupSummary>();
        foreach (var group in await access.ListNetworkGroupsAsync(cancellationToken))
        {
            var uses = await access.ListUsesOfNetworkGroupAsync(group.Key, cancellationToken);
            result.Add(new NetworkGroupSummary(group.Key, group.Name, group.Description, group.RangeList(), uses.Count(use => use.VaultId is not null), uses.Count(use => use.ApiKeyKey is not null)));
        }

        return result;
    }

    /// <summary>The groups by name, for someone who may attach one to their vault or key but not edit it.</summary>
    public async Task<IReadOnlyList<(int Key, string Name)>> ListNamesAsync(CancellationToken cancellationToken = default) =>
        [.. (await access.ListNetworkGroupsAsync(cancellationToken)).Select(group => (group.Key, group.Name))];

    public async Task CreateAsync(string name, string? description, string? ranges, Caller caller, CancellationToken cancellationToken = default)
    {
        Require(caller);
        Naming.Secret(name);
        var list = Networks.NormalizeAll(ranges);
        var group = new NetworkGroup
        {
            Name = name,
            NameLower = name.ToLowerInvariant(),
            Description = Describe(description),
            Ranges = string.Join('\n', list),
            CreatedUtc = clock.GetUtcNow().UtcDateTime,
        };
        if (!await access.AddNetworkGroupAsync(group, cancellationToken))
        {
            throw new DomainException("network.group.exists", $"A network group named '{name}' already exists.");
        }

        await audit.RecordAsync("network.group.created", caller, $"{name} = {Show(list)}", AuditSeverity.Notice, cancellationToken: cancellationToken);
    }

    /// <summary>
    /// Replaces a group's ranges. Adding a range opens every vault and key that lists the group to more of the
    /// network in one edit, so that is written as a security event; only taking ranges away is not.
    /// </summary>
    public async Task UpdateAsync(int key, string? description, string? ranges, Caller caller, CancellationToken cancellationToken = default)
    {
        Require(caller);
        var group = await access.FindNetworkGroupAsync(key, cancellationToken) ?? throw new DomainException("network.group.not_found", "That network group does not exist.");
        var before = group.RangeList();
        var after = Networks.NormalizeAll(ranges);
        group.Ranges = string.Join('\n', after);
        group.Description = Describe(description);
        await access.UpdateNetworkGroupAsync(group, cancellationToken);

        var uses = await access.ListUsesOfNetworkGroupAsync(key, cancellationToken);
        var widened = after.Except(before, StringComparer.Ordinal).Any();
        await audit.RecordAsync(
            "network.group.changed",
            caller,
            $"{group.Name}: {Show(before)} -> {Show(after)}; reaches {uses.Count(use => use.VaultId is not null).ToString(CultureInfo.InvariantCulture)} vaults, {uses.Count(use => use.ApiKeyKey is not null).ToString(CultureInfo.InvariantCulture)} keys",
            widened ? AuditSeverity.Security : AuditSeverity.Notice,
            cancellationToken: cancellationToken);
    }

    public async Task DeleteAsync(int key, Caller caller, CancellationToken cancellationToken = default)
    {
        Require(caller);
        var group = await access.FindNetworkGroupAsync(key, cancellationToken) ?? throw new DomainException("network.group.not_found", "That network group does not exist.");
        if (!await access.DeleteNetworkGroupAsync(key, cancellationToken))
        {
            throw new DomainException("network.group.in_use", $"'{group.Name}' is still listed by a vault or a key. Take it off those first.");
        }

        await audit.RecordAsync("network.group.deleted", caller, group.Name, AuditSeverity.Notice, cancellationToken: cancellationToken);
    }

    /// <summary>The lines of a vault's or key's list as people read them: group names resolved, ranges as they are.</summary>
    public static async Task<IReadOnlyList<NetworkLine>> LinesAsync(IAccessStore access, Guid? vaultId, int? apiKeyKey, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(access);
        var lines = await access.ListAllowedNetworksAsync(vaultId, apiKeyKey, cancellationToken);
        if (lines.Count == 0)
        {
            return [];
        }

        var groups = (await access.ListNetworkGroupsAsync(cancellationToken)).ToDictionary(group => group.Key);
        return [.. lines.Select(line => line.GroupKey is { } groupKey
            ? new NetworkLine(line.Key, groupKey, groups.TryGetValue(groupKey, out var group) ? group.Name : "(deleted group)", group?.RangeList() ?? [])
            : new NetworkLine(line.Key, null, line.Range!, [line.Range!]))];
    }

    /// <summary>A new line for a vault or a key: an existing group, or a literal range. Exactly one of the two.</summary>
    public static async Task<(AllowedNetwork Line, string Label)> NewLineAsync(IAccessStore access, Guid? vaultId, int? apiKeyKey, int? groupKey, string? range, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(access);
        if ((groupKey is null) == string.IsNullOrWhiteSpace(range))
        {
            throw new DomainException("network.line.invalid", "Choose a network group, or enter a range. One of the two.");
        }

        if (groupKey is { } key)
        {
            var group = await access.FindNetworkGroupAsync(key, cancellationToken) ?? throw new DomainException("network.group.not_found", "That network group does not exist.");
            return (new AllowedNetwork { VaultId = vaultId, ApiKeyKey = apiKeyKey, GroupKey = key }, group.Name);
        }

        var normalized = Networks.Normalize(range);
        return (new AllowedNetwork { VaultId = vaultId, ApiKeyKey = apiKeyKey, Range = normalized }, normalized);
    }

    private static string Show(IReadOnlyList<string> ranges) => ranges.Count == 0 ? "(none)" : string.Join(' ', ranges);

    private static string Describe(string? description) => (description ?? "").Trim() is { Length: <= 256 } text ? text : throw new DomainException("network.group.invalid", "The description is at most 256 characters.");

    private static void Require(Caller caller)
    {
        if (!caller.IsInstanceAdmin)
        {
            throw new DomainException("access.denied", "Only an administrator manages network groups.");
        }
    }
}
