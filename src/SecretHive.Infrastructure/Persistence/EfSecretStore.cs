using Microsoft.EntityFrameworkCore;
using SecretHive.Application.Ports;
using SecretHive.Domain.Entities;

namespace SecretHive.Infrastructure.Persistence;

/// <summary><see cref="ISecretStore"/> over EF Core. The context's change tracker is the unit of work.</summary>
public sealed class EfSecretStore(SecretHiveDbContext context) : ISecretStore
{
    public Task<Vault?> FindVaultAsync(string nameKey, CancellationToken cancellationToken) =>
        context.Vaults.FirstOrDefaultAsync(vault => vault.NameKey == nameKey, cancellationToken);

    public async Task<IReadOnlyList<Vault>> ListVaultsAsync(CancellationToken cancellationToken) =>
        await context.Vaults.OrderBy(vault => vault.NameKey).ToListAsync(cancellationToken);

    public async Task<IReadOnlyList<Folder>> ListFoldersAsync(CancellationToken cancellationToken) =>
        await context.Folders.OrderBy(folder => folder.NameKey).ToListAsync(cancellationToken);

    public Task<Folder?> FindFolderAsync(string nameKey, CancellationToken cancellationToken) =>
        context.Folders.FirstOrDefaultAsync(folder => folder.NameKey == nameKey, cancellationToken);

    public async Task<IReadOnlyDictionary<Guid, int>> CountLiveEntriesAsync(CancellationToken cancellationToken) =>
        await context.Entries.AsNoTracking().Where(entry => entry.BinKey == "")
            .GroupBy(entry => entry.VaultId).Select(group => new { group.Key, Count = group.Count() })
            .ToDictionaryAsync(group => group.Key, group => group.Count, cancellationToken);

    public async Task<IReadOnlyList<ChangedEntry>> ListChangedSinceAsync(IReadOnlyCollection<Guid> vaultIds, DateTime sinceUtc, int take, CancellationToken cancellationToken)
    {
        var ids = vaultIds.ToList();
        return await (
            from entry in context.Entries.AsNoTracking()
            where entry.BinKey == "" && ids.Contains(entry.VaultId)
            join value in context.Values.AsNoTracking() on entry.ValueId equals value.Id
            join version in context.Versions.AsNoTracking() on value.CurrentVersionId equals version.Id
            where version.CreatedUtc >= sinceUtc
            orderby version.CreatedUtc descending
            select new ChangedEntry(entry.VaultId, entry.Id, entry.Name, version.Number, version.CreatedUtc, version.CreatedBy))
            .Take(take).ToListAsync(cancellationToken);
    }

    public async Task<IReadOnlyList<EndingCertificate>> ListCertificatesEndingAsync(IReadOnlyCollection<Guid> vaultIds, DateTime beforeUtc, CancellationToken cancellationToken)
    {
        var ids = vaultIds.ToList();
        return await (
            from entry in context.Entries.AsNoTracking()
            where entry.BinKey == "" && ids.Contains(entry.VaultId)
            join value in context.Values.AsNoTracking() on entry.ValueId equals value.Id
            join certificate in context.Certificates.AsNoTracking() on value.CurrentVersionId equals certificate.VersionId
            where certificate.NotAfterUtc < beforeUtc
            orderby certificate.NotAfterUtc
            select new EndingCertificate(entry.VaultId, entry.Name, certificate.NotAfterUtc)).ToListAsync(cancellationToken);
    }

    public Task<int> CountAuditAsync(AuditSeverity severity, DateTime sinceUtc, CancellationToken cancellationToken) =>
        context.Audit.AsNoTracking().CountAsync(row => row.Severity == severity && row.AtUtc > sinceUtc, cancellationToken);

    public async Task<IReadOnlyList<Pin>> ListPinsAsync(int userKey, CancellationToken cancellationToken) =>
        await context.Pins.AsNoTracking().Where(pin => pin.UserKey == userKey).OrderBy(pin => pin.CreatedUtc).ToListAsync(cancellationToken);

    public async Task<bool> AddPinAsync(Pin pin, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(pin);
        if (await context.Pins.AnyAsync(other => other.UserKey == pin.UserKey && other.VaultId == pin.VaultId && other.EntryId == pin.EntryId, cancellationToken))
        {
            return false;
        }

        context.Pins.Add(pin);
        await context.SaveChangesAsync(cancellationToken);
        context.Entry(pin).State = EntityState.Detached;
        return true;
    }

    public async Task<bool> RemovePinAsync(int userKey, Guid vaultId, Guid? entryId, CancellationToken cancellationToken) =>
        await context.Pins.Where(pin => pin.UserKey == userKey && pin.VaultId == vaultId && pin.EntryId == entryId).ExecuteDeleteAsync(cancellationToken) > 0;

    public async Task<IReadOnlyList<SecretEntry>> ListEntriesOfValuesAsync(IReadOnlyCollection<Guid> valueIds, CancellationToken cancellationToken) =>
        await context.Entries.Include(entry => entry.Fields).Where(entry => valueIds.Contains(entry.ValueId)).ToListAsync(cancellationToken);

    public async Task<IReadOnlyList<SecretEntry>> ListLinkedEntriesAsync(CancellationToken cancellationToken)
    {
        var linked = context.Entries.GroupBy(entry => entry.ValueId).Where(group => group.Count() > 1).Select(group => group.Key);
        return await context.Entries.Include(entry => entry.Fields).Where(entry => linked.Contains(entry.ValueId)).ToListAsync(cancellationToken);
    }

    public async Task<IReadOnlyList<SecretEntry>> ListAllBinnedAsync(CancellationToken cancellationToken) =>
        await context.Entries.Include(entry => entry.Fields).Where(entry => entry.BinKey != "").ToListAsync(cancellationToken);

    public async Task<IReadOnlyList<StoredVersion>> ListVersionsAsync(Guid valueId, CancellationToken cancellationToken) =>
        await context.Versions.Include(version => version.Items).Where(version => version.ValueId == valueId).OrderBy(version => version.Number).ToListAsync(cancellationToken);

    public async Task<string?> GetSettingAsync(string key, CancellationToken cancellationToken) =>
        (await context.Settings.FindAsync([key], cancellationToken))?.Value;

    public async Task SetSettingAsync(string key, string? value, CancellationToken cancellationToken)
    {
        var setting = await context.Settings.FindAsync([key], cancellationToken);
        if (value is null)
        {
            if (setting is not null)
            {
                context.Settings.Remove(setting);
            }
        }
        else if (setting is null)
        {
            context.Settings.Add(new AppSetting { Key = key, Value = value });
        }
        else
        {
            setting.Value = value;
        }
    }

    public Task<SecretEntry?> FindEntryAsync(Guid vaultId, string nameKey, CancellationToken cancellationToken) =>
        context.Entries.Include(entry => entry.Fields)
            .FirstOrDefaultAsync(entry => entry.VaultId == vaultId && entry.NameKey == nameKey && entry.BinKey == "", cancellationToken);

    public Task<SecretEntry?> FindBinnedEntryAsync(Guid vaultId, Guid entryId, CancellationToken cancellationToken) =>
        context.Entries.Include(entry => entry.Fields)
            .FirstOrDefaultAsync(entry => entry.VaultId == vaultId && entry.Id == entryId && entry.BinKey != "", cancellationToken);

    public async Task<IReadOnlyList<SecretEntry>> ListEntriesAsync(Guid vaultId, bool inBin, CancellationToken cancellationToken) =>
        await context.Entries.Include(entry => entry.Fields)
            .Where(entry => entry.VaultId == vaultId && (entry.BinKey != "") == inBin)
            .ToListAsync(cancellationToken);

    public async Task<IReadOnlyDictionary<Guid, StoredValue>> GetValuesAsync(IReadOnlyCollection<Guid> ids, CancellationToken cancellationToken)
    {
        // Something added in this unit of work is not in the database yet, so look at what is tracked first.
        var found = context.Values.Local.Where(value => ids.Contains(value.Id)).ToDictionary(value => value.Id);
        var missing = ids.Where(id => !found.ContainsKey(id)).ToList();
        if (missing.Count > 0)
        {
            foreach (var value in await context.Values.Where(value => missing.Contains(value.Id)).ToListAsync(cancellationToken))
            {
                found[value.Id] = value;
            }
        }

        return found;
    }

    public Task<StoredVersion?> FindVersionAsync(Guid id, CancellationToken cancellationToken) =>
        context.Versions.Include(version => version.Items).FirstOrDefaultAsync(version => version.Id == id, cancellationToken);

    public async Task<IReadOnlyDictionary<Guid, StoredVersion>> GetVersionsAsync(IReadOnlyCollection<Guid> ids, CancellationToken cancellationToken) =>
        await context.Versions.Include(version => version.Items).Where(version => ids.Contains(version.Id)).ToDictionaryAsync(version => version.Id, cancellationToken);

    public async Task<int> LastVersionNumberAsync(Guid valueId, CancellationToken cancellationToken) =>
        await context.Versions.Where(version => version.ValueId == valueId).MaxAsync(version => (int?)version.Number, cancellationToken) ?? 0;

    public async Task<IReadOnlyDictionary<Guid, CertificateRecord>> GetCertificatesAsync(IReadOnlyCollection<Guid> versionIds, CancellationToken cancellationToken) =>
        await context.Certificates.Where(certificate => versionIds.Contains(certificate.VersionId)).ToDictionaryAsync(certificate => certificate.VersionId, cancellationToken);

    public async Task<IReadOnlyList<AuditEvent>> ListAuditAsync(int take, Guid? vaultId, string? vault, Guid? entryId, string? secret, long? beforeId, CancellationToken cancellationToken)
    {
        // Lower-cased on both sides: a name is found however it was typed, on either database. These calls are
        // translated to SQL, where the culture-aware overloads the analyzer asks for do not exist.
#pragma warning disable CA1304, CA1311, CA1862
        var rows = context.Audit.AsNoTracking();

        // A page further back: the rows older than the last one of the page before. The id only grows.
        if (beforeId is { } before)
        {
            rows = rows.Where(row => row.Id < before);
        }

        if (entryId is { } entry && vaultId is { } entryVault)
        {
            // The secret by id wherever it was; a row from before ids, by its vault and its present name.
            var vaultKey = (vault ?? "").ToLowerInvariant();
            var nameKey = (secret ?? "").ToLowerInvariant();
            return await rows
                .Where(row => row.EntryId == entry
                    || (row.EntryId == null && row.Secret != null && row.Secret.ToLower() == nameKey
                        && (row.VaultId == entryVault || (row.VaultId == null && row.Vault != null && row.Vault.ToLower() == vaultKey))))
                .OrderByDescending(row => row.Id).Take(take).ToListAsync(cancellationToken);
        }

        if (vaultId is { } id)
        {
            var key = (vault ?? "").ToLowerInvariant();
            rows = rows.Where(row => row.VaultId == id || (row.VaultId == null && row.Vault != null && row.Vault.ToLower() == key));
        }
        else if (vault is not null)
        {
            var key = vault.ToLowerInvariant();
            rows = rows.Where(row => row.Vault != null && row.Vault.ToLower() == key);
        }

        if (secret is not null)
        {
            var key = secret.ToLowerInvariant();
            rows = rows.Where(row => row.Secret != null && row.Secret.ToLower() == key);
        }

#pragma warning restore CA1304, CA1311, CA1862
        return await rows.OrderByDescending(row => row.Id).Take(take).ToListAsync(cancellationToken);
    }

    public void Add(Vault vault) => context.Vaults.Add(vault);

    public void Add(Folder folder) => context.Folders.Add(folder);

    public void Add(SecretEntry entry) => context.Entries.Add(entry);

    public void Add(StoredValue value) => context.Values.Add(value);

    public void Add(StoredVersion version) => context.Versions.Add(version);

    public void Add(CertificateRecord certificate) => context.Certificates.Add(certificate);

    public void Add(AuditEvent audit) => context.Audit.Add(audit);

    public async Task<IReadOnlyList<StoredVersion>> ListVersionsUnderOtherKeysAsync(string currentKeyId, IReadOnlyCollection<string> except, int take, CancellationToken cancellationToken)
    {
        var skip = except.ToList();
        return await context.Versions
            .Where(version => version.DataKeyId != currentKeyId && !skip.Contains(version.DataKeyId))
            .OrderBy(version => version.Id)
            .Take(take)
            .ToListAsync(cancellationToken);
    }

    public void Remove(EntryField field) => context.EntryFields.Remove(field);

    public void Remove(SecretEntry entry) => context.Entries.Remove(entry);

    public void Remove(StoredVersion version) => context.Versions.Remove(version);

    public void Remove(StoredValue value) => context.Values.Remove(value);

    public void Remove(Vault vault) => context.Vaults.Remove(vault);

    public void Remove(Folder folder) => context.Folders.Remove(folder);

    public Task SaveAsync(CancellationToken cancellationToken) => context.SaveChangesAsync(cancellationToken);
}
