using SecretHive.Application.Accounts;
using SecretHive.Domain;
using SecretHive.Domain.Entities;

namespace SecretHive.Application.Secrets;

/// <summary>
/// Where a vault may be used from. A vault with no networks listed is used from anywhere its roles allow; one
/// with any listed refuses everything about its secrets from an address outside them, whatever role the caller
/// holds, and writes that down. Deciding who has access and which networks are listed is not refused by the list
/// itself, so a wrong range can always be corrected by someone entitled to.
/// </summary>
public sealed partial class SecretService
{
    public async Task<IReadOnlyList<NetworkLine>> ListNetworksAsync(string vaultName, Caller caller, CancellationToken cancellationToken = default)
    {
        var vault = await RequireAccessManagerAsync(vaultName, caller, cancellationToken);
        return await NetworkService.LinesAsync(access, vault.Id, null, cancellationToken);
    }

    /// <summary>Adds a network group or a literal range to the networks a vault may be used from.</summary>
    public async Task AllowNetworkAsync(string vaultName, int? groupKey, string? range, Caller caller, CancellationToken cancellationToken = default)
    {
        var vault = await RequireAccessManagerAsync(vaultName, caller, cancellationToken);
        var (line, label) = await NetworkService.NewLineAsync(access, vault.Id, null, groupKey, range, cancellationToken);
        var first = (await access.ListAllowedNetworksAsync(vault.Id, null, cancellationToken)).Count == 0;
        if (!await access.AddAllowedNetworkAsync(line, cancellationToken))
        {
            throw new DomainException("network.line.exists", "That network is already listed.");
        }

        // The first line turns "from anywhere" into "only from here"; every later one opens the vault further.
        var audit = Audit("vault.network.added", caller, vault, detail: first ? $"{label} (the vault is now limited to its listed networks)" : label);
        audit.Severity = AuditSeverity.Notice;
        store.Add(audit);
        await store.SaveAsync(cancellationToken);
    }

    public async Task DisallowNetworkAsync(string vaultName, int lineKey, Caller caller, CancellationToken cancellationToken = default)
    {
        var vault = await RequireAccessManagerAsync(vaultName, caller, cancellationToken);
        var lines = await NetworkService.LinesAsync(access, vault.Id, null, cancellationToken);
        var line = lines.FirstOrDefault(candidate => candidate.Key == lineKey) ?? throw new DomainException("network.line.not_found", "That network is not listed.");
        await access.RemoveAllowedNetworkAsync(lineKey, vault.Id, null, cancellationToken);

        // Taking the last line away opens the vault to every address again: never a quiet change.
        var audit = Audit("vault.network.removed", caller, vault, detail: lines.Count == 1 ? $"{line.Label} (the vault is no longer limited to any network)" : line.Label);
        audit.Severity = lines.Count == 1 ? AuditSeverity.Security : AuditSeverity.Notice;
        store.Add(audit);
        await store.SaveAsync(cancellationToken);
    }

    /// <summary>
    /// Refuses a caller whose address is outside the vault's networks. The server's own jobs have no address and
    /// are not callers from a network; everyone else is held to the list, the bootstrap token included.
    /// </summary>
    private async Task RequireNetworkAsync(Vault vault, Caller caller, CancellationToken cancellationToken)
    {
        if (await NetworkAllowsAsync(vault, caller, cancellationToken))
        {
            return;
        }

        var refused = Audit("access.network.refused", caller, vault, detail: "outside the vault's networks");
        refused.Severity = AuditSeverity.Security;
        store.Add(refused);
        await store.SaveAsync(cancellationToken);
        throw new DomainException("access.network.refused", $"'{vault.Name}' is not used from this address.");
    }

    /// <summary>Whether the vault may be used from where the caller is, without writing anything down.</summary>
    private async Task<bool> NetworkAllowsAsync(Vault vault, Caller caller, CancellationToken cancellationToken)
    {
        if (caller is { Unrestricted: true, Via: "job", Address: null })
        {
            return true;
        }

        var ranges = await access.ResolveAllowedRangesAsync(vault.Id, null, cancellationToken);
        return ranges.Count == 0 || Networks.Contains(ranges, caller.Address);
    }
}
