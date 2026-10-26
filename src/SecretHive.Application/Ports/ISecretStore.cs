using SecretHive.Domain.Entities;

namespace SecretHive.Application.Ports;

/// <summary>
/// The database, as the use cases need it. One instance is one unit of work: everything added or changed through
/// it is written by a single <see cref="SaveAsync"/>, which is how a value read and its audit row stay together.
/// </summary>
public interface ISecretStore
{
    Task<Vault?> FindVaultAsync(string nameKey, CancellationToken cancellationToken);

    Task<IReadOnlyList<Vault>> ListVaultsAsync(CancellationToken cancellationToken);

    Task<IReadOnlyList<Folder>> ListFoldersAsync(CancellationToken cancellationToken);

    /// <summary>How many live secrets each vault holds, by vault id; a vault with none is left out.</summary>
    Task<IReadOnlyDictionary<Guid, int>> CountLiveEntriesAsync(CancellationToken cancellationToken);

    /// <summary>The live secrets of these vaults whose current version was made since, newest first.</summary>
    Task<IReadOnlyList<ChangedEntry>> ListChangedSinceAsync(IReadOnlyCollection<Guid> vaultIds, DateTime sinceUtc, int take, CancellationToken cancellationToken);

    /// <summary>The live certificates of these vaults whose current version ends before, soonest first.</summary>
    Task<IReadOnlyList<EndingCertificate>> ListCertificatesEndingAsync(IReadOnlyCollection<Guid> vaultIds, DateTime beforeUtc, CancellationToken cancellationToken);

    Task<int> CountAuditAsync(AuditSeverity severity, DateTime sinceUtc, CancellationToken cancellationToken);

    Task<IReadOnlyList<Pin>> ListPinsAsync(int userKey, CancellationToken cancellationToken);

    /// <summary>False when it was pinned already.</summary>
    Task<bool> AddPinAsync(Pin pin, CancellationToken cancellationToken);

    /// <summary>False when it was not pinned.</summary>
    Task<bool> RemovePinAsync(int userKey, Guid vaultId, Guid? entryId, CancellationToken cancellationToken);

    Task<Folder?> FindFolderAsync(string nameKey, CancellationToken cancellationToken);

    /// <summary>Every name, live or in a bin, that points at one of these values. More than one per value is a link.</summary>
    Task<IReadOnlyList<SecretEntry>> ListEntriesOfValuesAsync(IReadOnlyCollection<Guid> valueIds, CancellationToken cancellationToken);

    /// <summary>Every name, live or in a bin, of a value that has more than one: the linked ones.</summary>
    Task<IReadOnlyList<SecretEntry>> ListLinkedEntriesAsync(CancellationToken cancellationToken);

    /// <summary>What is in the bins of all vaults.</summary>
    Task<IReadOnlyList<SecretEntry>> ListAllBinnedAsync(CancellationToken cancellationToken);

    /// <summary>Every version of a value, with its items.</summary>
    Task<IReadOnlyList<StoredVersion>> ListVersionsAsync(Guid valueId, CancellationToken cancellationToken);

    Task<string?> GetSettingAsync(string key, CancellationToken cancellationToken);

    Task SetSettingAsync(string key, string? value, CancellationToken cancellationToken);

    /// <summary>The live entry of that name, with its fields.</summary>
    Task<SecretEntry?> FindEntryAsync(Guid vaultId, string nameKey, CancellationToken cancellationToken);

    /// <summary>An entry in the bin, by id: names are not unique there.</summary>
    Task<SecretEntry?> FindBinnedEntryAsync(Guid vaultId, Guid entryId, CancellationToken cancellationToken);

    /// <summary>The entries of a vault with their fields: the live ones, or the bin.</summary>
    Task<IReadOnlyList<SecretEntry>> ListEntriesAsync(Guid vaultId, bool inBin, CancellationToken cancellationToken);

    Task<IReadOnlyDictionary<Guid, StoredValue>> GetValuesAsync(IReadOnlyCollection<Guid> ids, CancellationToken cancellationToken);

    /// <summary>A version with its items.</summary>
    Task<StoredVersion?> FindVersionAsync(Guid id, CancellationToken cancellationToken);

    Task<IReadOnlyDictionary<Guid, StoredVersion>> GetVersionsAsync(IReadOnlyCollection<Guid> ids, CancellationToken cancellationToken);

    Task<int> LastVersionNumberAsync(Guid valueId, CancellationToken cancellationToken);

    /// <summary>What the certificate versions among these say about themselves.</summary>
    Task<IReadOnlyDictionary<Guid, CertificateRecord>> GetCertificatesAsync(IReadOnlyCollection<Guid> versionIds, CancellationToken cancellationToken);

    /// <summary>The newest audit rows first: all of them, those of one vault, or those of one secret in it.</summary>
    /// <summary>
    /// The newest rows first. With <paramref name="vaultId"/>, the rows about that vault whatever its name was then,
    /// and the rows from before vaults were recorded by id that carry <paramref name="vault"/> as their name; with
    /// only <paramref name="vault"/>, the rows that carry that name. With <paramref name="entryId"/>, the rows about
    /// that secret under any name and in any vault, and the older rows that carry its present vault and name.
    /// </summary>
    Task<IReadOnlyList<AuditEvent>> ListAuditAsync(int take, Guid? vaultId, string? vault, Guid? entryId, string? secret, long? beforeId, CancellationToken cancellationToken);

    void Add(Vault vault);

    void Add(Folder folder);

    void Add(SecretEntry entry);

    void Add(StoredValue value);

    void Add(StoredVersion version);

    void Add(CertificateRecord certificate);

    void Add(AuditEvent audit);

    /// <summary>
    /// Versions whose key is not under the given master key, to be changed and saved. <paramref name="except"/> are
    /// master keys already found to be unavailable, so the same rows are not handed out again and again.
    /// </summary>
    Task<IReadOnlyList<StoredVersion>> ListVersionsUnderOtherKeysAsync(string currentKeyId, IReadOnlyCollection<string> except, int take, CancellationToken cancellationToken);

    void Remove(EntryField field);

    void Remove(SecretEntry entry);

    /// <summary>Removes a vault. Its role assignments and its network list go with it; it must hold no secret.</summary>
    void Remove(Vault vault);

    void Remove(Folder folder);

    void Remove(StoredVersion version);

    void Remove(StoredValue value);

    Task SaveAsync(CancellationToken cancellationToken);
}

/// <summary>A live secret and its current version, for "recently changed".</summary>
public sealed record ChangedEntry(Guid VaultId, Guid EntryId, string Name, int Version, DateTime CreatedUtc, string CreatedBy);

/// <summary>A live certificate and when its current version ends.</summary>
public sealed record EndingCertificate(Guid VaultId, string Name, DateTime NotAfterUtc);
