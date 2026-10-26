using System.Globalization;
using SecretHive.Application.Ports;
using SecretHive.Domain;
using SecretHive.Domain.Entities;

namespace SecretHive.Application.Secrets;

/// <summary>
/// Moving, copying and linking between vaults, and what removal means once a value has several names.
/// A link is several equal names for one value: none is the original, and a new version set through any of them is
/// the current version of all.
/// </summary>
public sealed partial class SecretService
{
    private const string RetentionSetting = "bin.retention.days";

    /// <summary>
    /// Gives the value a second name in another vault. Both names are equals from then on. It takes a Secrets Officer
    /// of both vaults: whoever is that may already move the secret, history and all, to the other vault, which hands
    /// it over more completely than a link does. What a link adds (later versions follow, and the other vault's
    /// officers can change it) is why making one is a security event.
    /// </summary>
    public async Task LinkAsync(string vaultName, string name, string targetVaultName, string? targetName, Caller caller, CancellationToken cancellationToken = default)
    {
        var (vault, entry, target, newName) = await ResolveAsync("link", vaultName, name, targetVaultName, targetName, caller, VaultRole.SecretsOfficer, VaultRole.SecretsOfficer, cancellationToken);
        if (target.Id == vault.Id)
        {
            throw new DomainException("link.same_vault", "A link gives a value a name in another vault.");
        }

        // The new name starts with this one's description, which is its own from then on, and with the value's
        // ordinary fields, which every name of it shares.
        var linked = new SecretEntry { Id = Guid.NewGuid(), VaultId = target.Id, ValueId = entry.ValueId, Name = newName, NameKey = Key(newName), Description = entry.Description, CreatedUtc = Now() };
        SetFields(linked, [.. entry.Fields.Select(field => (field.Name, field.Type, field.Value))]);
        store.Add(linked);

        // A link lets the readers of one vault read, and its officers change, what the other holds.
        store.Add(Security(Audit("secret.link.created", caller, target, detail: $"{vault.Name}/{entry.Name}"), newName));
        await store.SaveAsync(cancellationToken);
    }

    /// <summary>
    /// Takes this name out of its link. It stays, as an independent secret holding the current version, marked as a
    /// copy. The other names are untouched.
    /// </summary>
    public async Task UnlinkAsync(string vaultName, string name, Caller caller, CancellationToken cancellationToken = default)
    {
        var vault = await RequireVaultAsync(vaultName, caller, VaultRole.SecretsOfficer, cancellationToken);
        var entry = await RequireEntryAsync(vault, name, cancellationToken);
        var others = await OtherNamesAsync(entry, cancellationToken);
        if (others.Count == 0)
        {
            throw new DomainException("secret.not_linked", $"'{name}' is not linked to anything.");
        }

        var (value, number) = await DuplicateValueAsync(entry.ValueId, caller, cancellationToken);
        entry.ValueId = value.Id;
        entry.CopiedFrom = string.Create(CultureInfo.InvariantCulture, $"{others[0]}/{number}");
        store.Add(Audit("secret.unlinked", caller, vault, entry, detail: string.Join(' ', others)));
        await store.SaveAsync(cancellationToken);
    }

    /// <summary>
    /// Makes a new, independent secret in another vault from the current version. It reads the value, so it is an
    /// audited read of the source; the copy records where it came from.
    /// </summary>
    public async Task CopyAsync(string vaultName, string name, string targetVaultName, string? targetName, Caller caller, CancellationToken cancellationToken = default)
    {
        var (vault, entry, target, newName) = await ResolveAsync("copy", vaultName, name, targetVaultName, targetName, caller, VaultRole.SecretsUser, VaultRole.SecretsOfficer, cancellationToken);
        var source = (await store.GetValuesAsync([entry.ValueId], cancellationToken))[entry.ValueId];
        var (value, number) = await DuplicateValueAsync(entry.ValueId, caller, cancellationToken);

        var copy = new SecretEntry
        {
            Id = Guid.NewGuid(),
            VaultId = target.Id,
            ValueId = value.Id,
            Name = newName,
            NameKey = Key(newName),
            Description = entry.Description,
            CreatedUtc = Now(),
            CopiedFrom = string.Create(CultureInfo.InvariantCulture, $"{vault.Name}/{entry.Name}/{number}"),
        };
        foreach (var field in entry.Fields)
        {
            copy.Fields.Add(new EntryField { Id = Guid.NewGuid(), EntryId = copy.Id, Name = field.Name, Type = field.Type, Value = field.Value });
        }

        store.Add(copy);
        store.Add(Audit("secret.value.read", caller, vault, entry, source.CurrentVersionId, "copy"));
        store.Add(Audit("secret.copied", caller, target, detail: $"{vault.Name}/{entry.Name}").Named(newName));
        await store.SaveAsync(cancellationToken);
    }

    /// <summary>Moves this name, with everything behind it, to another vault. Links to other names stay as they are.</summary>
    public async Task MoveAsync(string vaultName, string name, string targetVaultName, string? targetName, Caller caller, CancellationToken cancellationToken = default)
    {
        var (vault, entry, target, newName) = await ResolveAsync("move", vaultName, name, targetVaultName, targetName, caller, VaultRole.SecretsOfficer, VaultRole.SecretsOfficer, cancellationToken);
        if (target.Id == vault.Id)
        {
            throw new DomainException("move.same_vault", "The secret is already in that vault.");
        }

        // Out of a protected vault into an unprotected one is a way around the protection, so it takes the vault's admin.
        if (vault.PurgeProtection && !target.PurgeProtection)
        {
            await RequireVaultAsync(vaultName, caller, VaultRole.VaultAdmin, cancellationToken);
        }

        var from = $"{vault.Name}/{entry.Name}";
        entry.VaultId = target.Id;
        entry.Name = newName;
        entry.NameKey = Key(newName);

        // Leaving a vault with purge protection is leaving its protection, so that move is never a quiet one.
        var audit = Audit("secret.moved", caller, target, entry, detail: from);
        store.Add(vault.PurgeProtection && !target.PurgeProtection ? Security(audit) : audit);
        await store.SaveAsync(cancellationToken);
    }

    /// <summary>
    /// Gives a secret another name in its own vault. Its versions, fields, links and history stay with it: links and
    /// the audit trail point at it by id. What does not follow is every manifest and every <c>vault/name</c>
    /// reference outside the server, which have to be changed by hand.
    /// </summary>
    public async Task RenameSecretAsync(string vaultName, string name, string newName, Caller caller, CancellationToken cancellationToken = default)
    {
        var vault = await RequireVaultAsync(vaultName, caller, VaultRole.SecretsOfficer, cancellationToken);
        var entry = await RequireEntryAsync(vault, name, cancellationToken);
        Naming.Secret(newName);
        if (Key(newName) == entry.NameKey)
        {
            throw new DomainException("secret.rename.same", $"'{entry.Name}' already has that name.");
        }

        if (await store.FindEntryAsync(vault.Id, Key(newName), cancellationToken) is not null)
        {
            throw new DomainException("secret.name.taken", $"'{newName}' is in use in '{vault.Name}'.");
        }

        var old = entry.Name;
        entry.Name = newName;
        entry.NameKey = Key(newName);
        var renamed = Audit("secret.renamed", caller, vault, entry, detail: $"{old} -> {newName}");
        renamed.Severity = AuditSeverity.Notice;
        store.Add(renamed);
        await store.SaveAsync(cancellationToken);
    }

    /// <summary>The other live names of this secret, as <c>vault/name</c>.</summary>
    /// <remarks>Only the names in vaults the caller may see. That others exist is told by the listing, as a count.</remarks>
    public async Task<IReadOnlyList<string>> LinkedNamesAsync(string vaultName, string name, Caller caller, CancellationToken cancellationToken = default)
    {
        var vault = await RequireVaultAsync(vaultName, caller, VaultRole.Reader, cancellationToken);
        var entry = await RequireEntryAsync(vault, name, cancellationToken);
        var visible = await VisibleVaultsAsync(caller, cancellationToken);
        var vaults = (await store.ListVaultsAsync(cancellationToken)).ToDictionary(item => item.Id);
        return [.. (await store.ListEntriesOfValuesAsync([entry.ValueId], cancellationToken))
            .Where(other => other.Id != entry.Id && !other.InBin && visible.Contains(other.VaultId))
            .Select(other => $"{vaults[other.VaultId].Name}/{other.Name}")
            .Order(StringComparer.Ordinal)];
    }

    /// <summary>
    /// Moves the secret to the bin under every name it has. The caller has to say which names it expects to remove;
    /// if that is not exactly what is linked at this moment, nothing is deleted. A name added in between is never
    /// removed unseen.
    /// </summary>
    public async Task DeleteEverywhereAsync(string vaultName, string name, IReadOnlyCollection<string> expectedNames, Caller caller, CancellationToken cancellationToken = default)
    {
        var vault = await RequireVaultAsync(vaultName, caller, VaultRole.SecretsOfficer, cancellationToken);
        var entry = await RequireEntryAsync(vault, name, cancellationToken);
        var vaults = (await store.ListVaultsAsync(cancellationToken)).ToDictionary(item => item.Id);
        var all = (await store.ListEntriesOfValuesAsync([entry.ValueId], cancellationToken)).Where(item => !item.InBin).ToList();
        var actual = all.Select(item => $"{vaults[item.VaultId].Name}/{item.Name}").ToHashSet(StringComparer.OrdinalIgnoreCase);
        if (!actual.SetEquals(expectedNames))
        {
            throw new DomainException("secret.links.changed", "The names given are not exactly the names this secret has now. Nothing was deleted.");
        }

        // Under every name means in every one of those vaults: the right to delete is needed in each.
        foreach (var other in all.Select(item => vaults[item.VaultId]).DistinctBy(item => item.Id))
        {
            if (!(await RightsAsync(other, caller, cancellationToken) ?? VaultRights.None).HasFlag(VaultRights.Change))
            {
                throw new DomainException("access.denied", "Deleting it everywhere needs the role Secrets Officer in every vault it is linked into. Delete this name only.");
            }
        }

        foreach (var item in all)
        {
            ToBin(item, caller);
            store.Add(Audit("secret.deleted", caller, vaults[item.VaultId], item, detail: string.Join(' ', actual.Order(StringComparer.OrdinalIgnoreCase))));
        }

        await store.SaveAsync(cancellationToken);
    }

    /// <summary>What is in the bin of every vault: the administrator's overview.</summary>
    public async Task<IReadOnlyList<SecretSummary>> ListAllBinsAsync(Caller caller, CancellationToken cancellationToken = default)
    {
        RequireInstanceAdmin(caller, "see the bins of every vault");
        return await SummariseAsync(await store.ListAllBinnedAsync(cancellationToken), caller, cancellationToken);
    }

    /// <summary>
    /// Destroys a secret that is in the bin. The only thing that does. The value itself goes when its last name,
    /// binned ones included, is purged.
    /// </summary>
    public async Task PurgeAsync(string vaultName, Guid entryId, Caller caller, CancellationToken cancellationToken = default)
    {
        var vault = await RequireVaultAsync(vaultName, caller, VaultRole.VaultAdmin, cancellationToken);
        var entry = await store.FindBinnedEntryAsync(vault.Id, entryId, cancellationToken)
            ?? throw new DomainException("secret.not_in_bin", "That secret is not in the bin of this vault.");
        if (vault.PurgeProtection)
        {
            throw new DomainException("vault.purge_protected", $"'{vault.Name}' has purge protection: nothing in it can be purged by hand.");
        }

        await PurgeAsync(vault, entry, caller, cancellationToken);
        await store.SaveAsync(cancellationToken);
    }

    public async Task SetPurgeProtectionAsync(string vaultName, bool enabled, Caller caller, CancellationToken cancellationToken = default)
    {
        var vault = await RequireVaultAsync(vaultName, caller, VaultRole.VaultAdmin, cancellationToken);

        // On is the vault admin's call. Off removes a protection the vault was promised, so it takes a super admin.
        if (!enabled && !(caller.Unrestricted || caller.Role == UserRole.SuperAdmin))
        {
            throw new DomainException("access.denied", "Only a super admin can switch purge protection off.");
        }

        vault.PurgeProtection = enabled;
        var audit = Audit(enabled ? "vault.purge_protection.enabled" : "vault.purge_protection.disabled", caller, vault);
        store.Add(enabled ? audit : Security(audit));
        await store.SaveAsync(cancellationToken);
    }

    /// <summary>After how many days the bins are emptied, or null when they never are. Null is the default.</summary>
    public async Task<int?> GetRetentionDaysAsync(CancellationToken cancellationToken = default) =>
        int.TryParse(await store.GetSettingAsync(RetentionSetting, cancellationToken), NumberStyles.None, CultureInfo.InvariantCulture, out var days) ? days : null;

    public async Task SetRetentionDaysAsync(int? days, Caller caller, CancellationToken cancellationToken = default)
    {
        RequireInstanceAdmin(caller, "change how long the bins are kept");
        if (days is < 1 or > 3650)
        {
            throw new DomainException("retention.days.invalid", "Retention is between 1 and 3650 days, or off.");
        }

        await store.SetSettingAsync(RetentionSetting, days?.ToString(CultureInfo.InvariantCulture), cancellationToken);
        var audit = new AuditEvent
        {
            AtUtc = Now(),
            Code = days is null ? "bin.retention.disabled" : "bin.retention.enabled",
            Severity = days is null ? AuditSeverity.Notice : AuditSeverity.Security,
            Principal = caller.Principal,
            Address = caller.Address,
            Via = caller.Via,
            Detail = days?.ToString(CultureInfo.InvariantCulture),
        };
        store.Add(audit);
        await store.SaveAsync(cancellationToken);
    }

    /// <summary>
    /// Empties what has been in a bin longer than the retention period. Does nothing while retention is off.
    /// Returns how many names were destroyed.
    /// </summary>
    public async Task<int> PurgeExpiredAsync(CancellationToken cancellationToken = default)
    {
        if (await GetRetentionDaysAsync(cancellationToken) is not { } days)
        {
            return 0;
        }

        var vaults = (await store.ListVaultsAsync(cancellationToken)).ToDictionary(vault => vault.Id);
        var limit = Now().AddDays(-days);
        var expired = (await store.ListAllBinnedAsync(cancellationToken)).Where(entry => entry.DeletedUtc < limit).ToList();
        foreach (var entry in expired)
        {
            await PurgeAsync(vaults[entry.VaultId], entry, Caller.System("retention"), cancellationToken);
        }

        await store.SaveAsync(cancellationToken);
        return expired.Count;
    }

    private async Task PurgeAsync(Vault vault, SecretEntry entry, Caller caller, CancellationToken cancellationToken)
    {
        store.Add(Security(Audit("secret.purged", caller, vault, entry)));
        var others = (await store.ListEntriesOfValuesAsync([entry.ValueId], cancellationToken)).Where(other => other.Id != entry.Id && !_purged.Contains(other.Id)).ToList();
        _purged.Add(entry.Id);
        store.Remove(entry);
        if (others.Count > 0)
        {
            return;
        }

        foreach (var version in await store.ListVersionsAsync(entry.ValueId, cancellationToken))
        {
            store.Remove(version);
        }

        store.Remove((await store.GetValuesAsync([entry.ValueId], cancellationToken))[entry.ValueId]);
    }

    // Names removed in this unit of work: they are still in the database until it is saved.
    private readonly HashSet<Guid> _purged = [];

    private async Task<(Vault Vault, SecretEntry Entry, Vault Target, string NewName)> ResolveAsync(string what, string vaultName, string name, string targetVaultName, string? targetName, Caller caller, VaultRole here, VaultRole there, CancellationToken cancellationToken)
    {
        var vault = await RequireVaultAsync(vaultName, caller, here, cancellationToken);
        var entry = await RequireEntryAsync(vault, name, cancellationToken);

        // Too low a role in the other vault: on record under this secret, where it was tried and where whoever
        // looks at what happened to it will look, naming the vault it was meant for.
        if (await store.FindVaultAsync(Key(targetVaultName), cancellationToken) is { } wanted
            && await RightsAsync(wanted, caller, cancellationToken) is { } rights && !rights.HasFlag(VaultRoles.Needs(there)))
        {
            var held = VaultRoles.Named(rights);
            var denied = Audit("access.denied", caller, vault, entry, detail: $"{what} into {wanted.Name} needs {RoleName(there)} there, has {RoleName(held)}");
            denied.Severity = AuditSeverity.Notice;
            store.Add(denied);
            await store.SaveAsync(cancellationToken);
            throw new DomainException("access.denied", $"That needs the role {RoleName(there)} in '{wanted.Name}'; you have {RoleName(held)}.");
        }

        var target = await RequireVaultAsync(targetVaultName, caller, there, cancellationToken);
        var newName = Naming.Secret(string.IsNullOrEmpty(targetName) ? entry.Name : targetName);
        if (await store.FindEntryAsync(target.Id, Key(newName), cancellationToken) is not null)
        {
            throw new DomainException("secret.name.taken", $"'{newName}' is in use in '{target.Name}'.");
        }

        return (vault, entry, target, newName);
    }

    private async Task<IReadOnlyList<string>> OtherNamesAsync(SecretEntry entry, CancellationToken cancellationToken)
    {
        var vaults = (await store.ListVaultsAsync(cancellationToken)).ToDictionary(vault => vault.Id);
        return [.. (await store.ListEntriesOfValuesAsync([entry.ValueId], cancellationToken))
            .Where(other => other.Id != entry.Id && !other.InBin)
            .Select(other => $"{vaults[other.VaultId].Name}/{other.Name}")
            .Order(StringComparer.Ordinal)];
    }

    /// <summary>
    /// A new value holding the current version of another, encrypted again under a key of its own. A ciphertext is
    /// tied to its value and version, so a copy cannot share bytes with what it was copied from.
    /// </summary>
    private async Task<(StoredValue Value, int SourceVersion)> DuplicateValueAsync(Guid valueId, Caller caller, CancellationToken cancellationToken)
    {
        var source = (await store.GetValuesAsync([valueId], cancellationToken))[valueId];
        var sourceVersion = await store.FindVersionAsync(source.CurrentVersionId, cancellationToken)
            ?? throw new DomainException("secret.version.missing", "The secret has no current version.");
        var sealedSource = new SealedVersion(
            Blob.UnpackKey(sourceVersion.DataKeyId, sourceVersion.DataKey),
            sourceVersion.Items.ToDictionary(item => item.Slot, item => Blob.UnpackItem(item.Content), StringComparer.Ordinal));

        var value = new StoredValue
        {
            Id = Guid.NewGuid(),
            Kind = source.Kind,
            ContentType = source.ContentType,
            NotBeforeUtc = source.NotBeforeUtc,
            ExpiresUtc = source.ExpiresUtc,
            CreatedUtc = Now(),
        };
        var versionId = Guid.NewGuid();
        var opened = new List<SecretBytes>();
        var copies = new List<byte[]>();
        try
        {
            var plain = new Dictionary<string, ReadOnlyMemory<byte>>(StringComparer.Ordinal);
            foreach (var item in sourceVersion.Items)
            {
                var bytes = keyRing.Open(new VersionAddress(source.Id, sourceVersion.Id), sealedSource, item.Slot);
                opened.Add(bytes);
                var copy = bytes.Reveal().ToArray();
                copies.Add(copy);
                plain[item.Slot] = copy;
            }

            var sealedCopy = keyRing.Seal(new VersionAddress(value.Id, versionId), plain);
            var version = new StoredVersion
            {
                Id = versionId,
                ValueId = value.Id,
                Number = 1,
                CreatedUtc = Now(),
                CreatedBy = caller.Principal,
                DataKeyId = sealedCopy.Key.MasterKeyId,
                DataKey = Blob.Pack(sealedCopy.Key),
            };
            foreach (var item in sourceVersion.Items)
            {
                version.Items.Add(new VersionItem { Id = Guid.NewGuid(), VersionId = versionId, Slot = item.Slot, FieldType = item.FieldType, FileName = item.FileName, Content = Blob.Pack(sealedCopy.Items[item.Slot]) });
            }

            value.CurrentVersionId = versionId;
            store.Add(value);
            store.Add(version);
            if ((await store.GetCertificatesAsync([sourceVersion.Id], cancellationToken)).GetValueOrDefault(sourceVersion.Id) is { } facts)
            {
                store.Add(new CertificateRecord
                {
                    VersionId = versionId,
                    Subject = facts.Subject,
                    Issuer = facts.Issuer,
                    Serial = facts.Serial,
                    Thumbprint = facts.Thumbprint,
                    Sha1Thumbprint = facts.Sha1Thumbprint,
                    NotBeforeUtc = facts.NotBeforeUtc,
                    NotAfterUtc = facts.NotAfterUtc,
                    AlternativeNames = facts.AlternativeNames,
                });
            }

            return (value, sourceVersion.Number);
        }
        finally
        {
            foreach (var bytes in opened)
            {
                bytes.Dispose();
            }

            foreach (var copy in copies)
            {
                System.Security.Cryptography.CryptographicOperations.ZeroMemory(copy);
            }
        }
    }

    private void ToBin(SecretEntry entry, Caller caller)
    {
        entry.BinKey = entry.Id.ToString("N");
        entry.DeletedUtc = Now();
        entry.DeletedBy = caller.Principal;
    }

    /// <summary>
    /// Makes every name of a linked value carry the same ordinary fields. Until 0.29 each name kept its own; since
    /// then they are the value's. Run at every start and does nothing once they agree. Where names disagree on a
    /// field, the oldest name's wins; each value that changes gets one audit row that names the fields and the
    /// names, never what was in them. Returns how many values changed.
    /// </summary>
    public async Task<int> AlignLinkedFieldsAsync(Caller caller, CancellationToken cancellationToken = default)
    {
        var vaults = (await store.ListVaultsAsync(cancellationToken)).ToDictionary(vault => vault.Id);
        var changed = 0;
        foreach (var names in (await store.ListLinkedEntriesAsync(cancellationToken)).GroupBy(entry => entry.ValueId))
        {
            var ordered = names.OrderBy(entry => entry.CreatedUtc).ThenBy(entry => entry.Id).ToList();
            string Label(SecretEntry entry) => $"{vaults[entry.VaultId].Name}/{entry.Name}";

            var merged = new List<(string Name, FieldType Type, string Value)>();
            var notes = new List<string>();
            foreach (var group in ordered.SelectMany(entry => entry.Fields.Select(field => (Entry: entry, Field: field))).GroupBy(item => item.Field.Name, StringComparer.OrdinalIgnoreCase))
            {
                var kept = group.First();
                merged.Add((kept.Field.Name, kept.Field.Type, kept.Field.Value));
                var replaced = group.Where(item => item.Field.Value != kept.Field.Value || item.Field.Type != kept.Field.Type).Select(item => Label(item.Entry)).ToList();
                var added = ordered.Where(entry => !group.Any(item => item.Entry.Id == entry.Id)).Select(Label).ToList();
                if (replaced.Count > 0 || added.Count > 0)
                {
                    notes.Add($"{kept.Field.Name}: kept from {Label(kept.Entry)}"
                        + (replaced.Count > 0 ? $", replaced on {string.Join(", ", replaced)}" : "")
                        + (added.Count > 0 ? $", added on {string.Join(", ", added)}" : ""));
                }
            }

            static string Shape(IEnumerable<(string Name, FieldType Type, string Value)> fields) =>
                string.Join('\n', fields.OrderBy(field => field.Name, StringComparer.OrdinalIgnoreCase).Select(field => $"{field.Name}\t{field.Type}\t{field.Value}"));
            var target = Shape(merged);
            var differing = ordered.Where(entry => Shape(entry.Fields.Select(field => (field.Name, field.Type, field.Value))) != target).ToList();
            if (differing.Count == 0)
            {
                continue;
            }

            foreach (var entry in ordered)
            {
                SetFields(entry, merged);
            }

            var first = ordered[0];
            store.Add(Audit("secret.fields.aligned", caller, vaults[first.VaultId], first, detail: string.Join("; ", notes)));
            changed++;
        }

        if (changed > 0)
        {
            await store.SaveAsync(cancellationToken);
        }

        return changed;
    }

    private static AuditEvent Security(AuditEvent audit, string? secret = null)
    {
        audit.Severity = AuditSeverity.Security;
        audit.Secret = secret ?? audit.Secret;
        return audit;
    }
}

internal static class AuditEventExtensions
{
    public static AuditEvent Named(this AuditEvent audit, string secret)
    {
        audit.Secret = secret;
        return audit;
    }
}
