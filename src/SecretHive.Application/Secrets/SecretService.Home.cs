using SecretHive.Application.Ports;
using SecretHive.Domain;
using SecretHive.Domain.Entities;

namespace SecretHive.Application.Secrets;

/// <summary>A vault on the home page: where it is, the caller's role, how many secrets it holds, and whether it is pinned.</summary>
/// <remarks><see cref="Secrets"/> is null where the vault's networks refuse the caller: what is in it is not said from here.</remarks>
public sealed record HomeVault(string Name, string? Description, VaultRole Role, IReadOnlyList<string> Folders, int? Secrets, bool Pinned);

/// <summary>A pinned secret, by vault and name.</summary>
public sealed record HomeSecret(string Vault, string Name, string? Description);

/// <summary>A secret whose current version was made lately.</summary>
public sealed record HomeChange(string Vault, string Secret, int Version, DateTime AtUtc, string By);

/// <summary>A certificate that ends soon, or has ended.</summary>
public sealed record HomeCertificate(string Vault, string Secret, DateTime NotAfterUtc);

/// <summary>
/// Everything the home page shows from the vaults, in one go: the caller's vaults with counts, their pins, what changed
/// in the last week, the certificates that end within 30 days, and, for an administrator, how many security events
/// the last day held. Nothing in it reads a value, and none of it is on record.
/// </summary>
public sealed record HomeView(IReadOnlyList<HomeVault> Vaults, IReadOnlyList<HomeSecret> PinnedSecrets, IReadOnlyList<HomeChange> Changed, IReadOnlyList<HomeCertificate> Ending, int? SecurityEvents24h);

public sealed partial class SecretService
{
    public const int ChangedDays = 7;
    public const int ChangedRows = 10;
    public const int EndingDays = 30;

    public async Task<HomeView> HomeAsync(Caller caller, CancellationToken cancellationToken = default)
    {
        var now = Now();
        var folders = await store.ListFoldersAsync(cancellationToken);
        var parents = folders.ToDictionary(folder => folder.Id, folder => folder.ParentId);
        var byId = folders.ToDictionary(folder => folder.Id);
        var counts = await store.CountLiveEntriesAsync(cancellationToken);
        var pins = caller.UserKey is { } me ? await store.ListPinsAsync(me, cancellationToken) : [];

        // A vault the caller has a role in is listed; what is in it only where its networks let the caller in, as
        // for its own page.
        var vaults = new List<HomeVault>();
        var open = new Dictionary<Guid, Vault>();
        foreach (var vault in await store.ListVaultsAsync(cancellationToken))
        {
            if (await EffectiveRoleAsync(vault, caller, cancellationToken) is not { } role)
            {
                continue;
            }

            var reachable = await NetworkAllowsAsync(vault, caller, cancellationToken);
            if (reachable)
            {
                open[vault.Id] = vault;
            }

            vaults.Add(new HomeVault(
                vault.Name,
                vault.Description,
                role,
                PathOf(vault.FolderId, parents, byId),
                reachable ? counts.GetValueOrDefault(vault.Id) : null,
                pins.Any(pin => pin.VaultId == vault.Id && pin.EntryId is null)));
        }

        var pinned = new List<HomeSecret>();
        foreach (var group in pins.Where(pin => pin.EntryId is not null && open.ContainsKey(pin.VaultId)).GroupBy(pin => pin.VaultId))
        {
            var entries = (await store.ListEntriesAsync(group.Key, inBin: false, cancellationToken)).ToDictionary(entry => entry.Id);
            pinned.AddRange(group.Where(pin => entries.ContainsKey(pin.EntryId!.Value))
                .Select(pin => entries[pin.EntryId!.Value])
                .Select(entry => new HomeSecret(open[group.Key].Name, entry.Name, entry.Description)));
        }

        var ids = open.Keys.ToList();
        var changed = (await store.ListChangedSinceAsync(ids, now.AddDays(-ChangedDays), ChangedRows, cancellationToken))
            .Select(entry => new HomeChange(open[entry.VaultId].Name, entry.Name, entry.Version, entry.CreatedUtc, entry.CreatedBy)).ToList();
        var ending = (await store.ListCertificatesEndingAsync(ids, now.AddDays(EndingDays), cancellationToken))
            .Select(certificate => new HomeCertificate(open[certificate.VaultId].Name, certificate.Name, certificate.NotAfterUtc)).ToList();
        int? security = caller.IsInstanceAdmin ? await store.CountAuditAsync(AuditSeverity.Security, now.AddHours(-24), cancellationToken) : null;

        return new HomeView(
            [.. vaults.OrderBy(vault => string.Join('/', vault.Folders), StringComparer.OrdinalIgnoreCase).ThenBy(vault => vault.Name, StringComparer.OrdinalIgnoreCase)],
            [.. pinned.OrderBy(secret => secret.Vault, StringComparer.OrdinalIgnoreCase).ThenBy(secret => secret.Name, StringComparer.OrdinalIgnoreCase)],
            changed,
            ending,
            security);
    }

    /// <summary>The caller's pins it may still see, as vault and secret (null: the vault itself).</summary>
    public async Task<IReadOnlyList<(string Vault, string? Secret)>> ListPinsAsync(Caller caller, CancellationToken cancellationToken = default)
    {
        var view = await HomeAsync(caller, cancellationToken);
        return [.. view.Vaults.Where(vault => vault.Pinned).Select(vault => (vault.Name, (string?)null)),
            .. view.PinnedSecrets.Select(secret => (secret.Vault, (string?)secret.Name))];
    }

    /// <summary>Whether the caller pinned this vault, or this secret in it. False for anything they may not see.</summary>
    public async Task<bool> IsPinnedAsync(string vaultName, string? secret, Caller caller, CancellationToken cancellationToken = default)
    {
        if (caller.UserKey is not { } me || await store.FindVaultAsync(Key(vaultName), cancellationToken) is not { } vault
            || await EffectiveRoleAsync(vault, caller, cancellationToken) is null)
        {
            return false;
        }

        var entryId = secret is null ? null : (await store.FindEntryAsync(vault.Id, Key(secret), cancellationToken))?.Id;
        if (secret is not null && entryId is null)
        {
            return false;
        }

        return (await store.ListPinsAsync(me, cancellationToken)).Any(pin => pin.VaultId == vault.Id && pin.EntryId == entryId);
    }

    /// <summary>
    /// Pins a vault, or a secret in it, to the caller's home page, or takes the pin away. Only an account keeps pins;
    /// pinning takes no more than seeing what is pinned, and is not on record: it shows nothing new.
    /// </summary>
    public async Task SetPinAsync(string vaultName, string? secret, bool pinned, Caller caller, CancellationToken cancellationToken = default)
    {
        if (caller.UserKey is not { } me)
        {
            throw new DomainException("pin.no_account", "Only an account keeps pins.");
        }

        var vault = await RequireVaultAsync(vaultName, caller, VaultRole.Reader, cancellationToken);
        var entryId = secret is null ? (Guid?)null : (await RequireEntryAsync(vault, secret, cancellationToken)).Id;
        if (pinned)
        {
            await store.AddPinAsync(new Pin { UserKey = me, VaultId = vault.Id, EntryId = entryId, CreatedUtc = Now() }, cancellationToken);
        }
        else
        {
            await store.RemovePinAsync(me, vault.Id, entryId, cancellationToken);
        }
    }
}
