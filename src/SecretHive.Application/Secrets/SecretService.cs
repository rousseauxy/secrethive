using System.Text;
using SecretHive.Application.Ports;
using SecretHive.Domain;
using SecretHive.Domain.Entities;

namespace SecretHive.Application.Secrets;

/// <summary>Who is asking, from where and through what. Goes on every audit row.</summary>
public sealed record Caller(
    string Principal,
    string? Address = null,
    string Via = "api",
    int? UserKey = null,
    UserRole Role = UserRole.User,
    bool Unrestricted = false,
    int? KeyId = null,
    Guid? OnlyVault = null,
    VaultRole? MaxRole = null,
    IReadOnlyList<int>? Groups = null,
    bool KeyOfAdminService = false)
{
    /// <summary>
    /// Creates vaults, hands out roles and manages what belongs to the whole instance. Not a right to read values:
    /// that takes a role in the vault, for an administrator as for anyone.
    /// </summary>
    /// <remarks>
    /// A person's key never: it reads and writes secrets as its owner, and manages nothing. The one key that does is
    /// one of a service identity a super admin made an admin (<see cref="KeyOfAdminService"/>), and then as an admin,
    /// never as a super admin.
    /// </remarks>
    public bool IsInstanceAdmin => Unrestricted || (Role >= UserRole.Admin && (KeyId is null || KeyOfAdminService));

    /// <summary>The server itself, for work nobody asked for by name: the retention job.</summary>
    public static Caller System(string name) => new(name, Via: "job", Unrestricted: true);
}

public sealed record FieldInput(string Name, ReadOnlyMemory<byte> Value, FieldType Type = FieldType.Text, bool Sensitive = false);

public sealed record SetSecret(
    string Vault,
    string Name,
    ReadOnlyMemory<byte> Value,
    string? ContentType = null,
    string? Description = null,
    IReadOnlyList<FieldInput>? Fields = null,
    bool KeepDetails = false,
    IReadOnlyList<string>? KeepSensitiveFields = null,
    bool Merge = false);

public sealed record VaultSummary(string Name, string? Description, bool PurgeProtection, DateTime CreatedUtc, string? Folder = null);

/// <summary>
/// A vault as the list beside the pages shows it: its name, the role the caller has in it, and the folders it is in
/// from the top down (empty at the top).
/// </summary>
public sealed record VaultPlace(string Name, string? Description, VaultRole Role, IReadOnlyList<string> Folders);

/// <summary>Decrypted bytes and the version they belong to.</summary>
public sealed record Revealed(SecretBytes Bytes, Guid VersionId, int Version) : IDisposable
{
    public void Dispose() => Bytes.Dispose();
}

public sealed record ImportCertificate(string Vault, string Name, IReadOnlyList<CertificatePart> Parts, string? Description = null);

/// <summary>One stored part of a certificate version, without its content.</summary>
public sealed record PartSummary(string Kind, string? FileName, bool Private);

/// <summary>A part's bytes and the file name it was supplied under.</summary>
public sealed record RevealedPart(Revealed Content, string? FileName) : IDisposable
{
    public void Dispose() => Content.Dispose();
}

/// <summary>What a Reader may see of a secret or a certificate: everything but values, sensitive fields and private parts.</summary>
public sealed record SecretSummary(
    Guid EntryId,
    string Name,
    ValueKind Kind,
    bool Enabled,
    string? Description,
    string? ContentType,
    Guid VersionId,
    int Version,
    DateTime VersionCreatedUtc,
    IReadOnlyDictionary<string, string> Fields,
    IReadOnlyList<string> SensitiveFields,
    DateTime? DeletedUtc,
    string? DeletedBy,
    CertificateFacts? Certificate = null,
    IReadOnlyList<PartSummary>? Parts = null,
    string Vault = "",
    IReadOnlyList<string>? LinkedWith = null,
    string? CopiedFrom = null,
    int LinkedElsewhere = 0)
{
    /// <summary>Whether this value has other names at all, including ones in vaults the reader may not see.</summary>
    public bool IsLinked => LinkedWith is { Count: > 0 } || LinkedElsewhere > 0;
}

/// <summary>
/// The use cases for vaults and secrets. Every change and every value read writes its audit row in the same save
/// as the change or the read itself: there is no path that reads a value and can fail to record it.
/// </summary>
public sealed partial class SecretService(ISecretStore store, IKeyRing keyRing, TimeProvider clock, IAccessStore access, IUserStore users)
{
    public const string ValueSlot = "value";

    public async Task CreateVaultAsync(string name, string? description, Caller caller, string? folder = null, CancellationToken cancellationToken = default)
    {
        RequireInstanceAdmin(caller, "create a vault");
        Naming.Vault(name);
        if (await store.FindVaultAsync(Key(name), cancellationToken) is not null)
        {
            throw new DomainException("vault.exists", $"A vault named '{name}' already exists.");
        }

        // Made in a folder, it inherits what that folder gives from the start: said on the creation, as a move would.
        var into = folder is null ? null : await RequireFolderAsync(folder, cancellationToken);
        var change = into is null ? ("", false) : await DescribeChangeAsync(null, into.Id, cancellationToken);
        var vault = new Vault { Id = Guid.NewGuid(), Name = name, NameKey = Key(name), Description = NullIfEmpty(description), CreatedUtc = Now(), FolderId = into?.Id };
        store.Add(vault);
        var created = Audit("vault.created", caller, vault, detail: into is null ? null : Cap($"in {into.Name}{change.Item1}"));
        created.Severity = change.Item2 ? AuditSeverity.Security : created.Severity;
        store.Add(created);
        await store.SaveAsync(cancellationToken);

        // Whoever makes a vault runs it, until they say otherwise.
        if (caller.UserKey is { } creator)
        {
            await access.SetAssignmentAsync(
                new VaultAssignment { VaultId = vault.Id, UserKey = creator, Role = VaultRole.VaultAdmin, GrantedUtc = Now(), GrantedBy = caller.Principal },
                cancellationToken);
        }
    }

    /// <summary>
    /// Gives a vault another name. Everything in it stays: roles, keys and networks point at it by id, and so do the
    /// links into it. What does not follow is every manifest and every <c>vault/name</c> reference outside the
    /// server, which is why only an instance administrator may, as for creating and deleting one, and why it is a
    /// security event. The audit rows keep the name the vault had when they were written.
    /// </summary>
    public async Task RenameVaultAsync(string name, string newName, Caller caller, CancellationToken cancellationToken = default)
    {
        RequireInstanceAdmin(caller, "rename a vault");
        var vault = await store.FindVaultAsync(Key(name), cancellationToken)
            ?? throw new DomainException("vault.not_found", $"There is no vault '{name}'.");
        Naming.Vault(newName);
        if (Key(newName) == vault.NameKey)
        {
            throw new DomainException("vault.rename.same", $"'{vault.Name}' already has that name.");
        }

        if (await store.FindVaultAsync(Key(newName), cancellationToken) is not null)
        {
            throw new DomainException("vault.exists", $"A vault named '{newName}' already exists.");
        }

        var old = vault.Name;
        vault.Name = newName;
        vault.NameKey = Key(newName);
        store.Add(Security(Audit("vault.renamed", caller, vault, detail: $"{old} -> {newName}")));
        await store.SaveAsync(cancellationToken);
    }

    /// <summary>
    /// Removes a vault that holds nothing: no secret, and nothing in its bin. It never destroys a value on the way;
    /// whatever is in the vault has to be deleted and purged first, each of which is its own decision on record.
    /// The roles given in the vault and its network list go with it.
    /// </summary>
    public async Task DeleteVaultAsync(string name, Caller caller, CancellationToken cancellationToken = default)
    {
        if (!(caller.Unrestricted || (caller.Role == UserRole.SuperAdmin && caller.IsInstanceAdmin)))
        {
            throw new DomainException("access.denied", "Only a super admin can delete a vault.");
        }

        var vault = await store.FindVaultAsync(Key(name), cancellationToken)
            ?? throw new DomainException("vault.not_found", $"There is no vault '{name}'.");
        var live = (await store.ListEntriesAsync(vault.Id, inBin: false, cancellationToken)).Count;
        var binned = (await store.ListEntriesAsync(vault.Id, inBin: true, cancellationToken)).Count;
        if (live > 0 || binned > 0)
        {
            throw new DomainException(
                "vault.not_empty",
                string.Create(System.Globalization.CultureInfo.InvariantCulture, $"'{vault.Name}' is not empty: {live} in the vault, {binned} in its bin. Delete and purge them first."));
        }

        store.Add(Security(Audit("vault.deleted", caller, vault)));
        store.Remove(vault);
        await store.SaveAsync(cancellationToken);
    }

    /// <summary>Creates the secret, or gives it a new version. Returns the new version's number.</summary>
    public async Task<int> SetAsync(SetSecret request, Caller caller, CancellationToken cancellationToken = default)
    {
        Naming.Secret(request.Name);
        if (request.Value.IsEmpty)
        {
            throw new DomainException("secret.value.empty", "A secret cannot be empty.");
        }

        SecretLimits.ValidateValue(request.Value.Span, request.ContentType);

        // Merging: what the request does not name stays as it is, and a field named with nothing in it is taken away.
        var taken = request.Merge
            ? (request.Fields ?? []).Where(input => input.Value.IsEmpty).Select(input => input.Name).ToHashSet(StringComparer.OrdinalIgnoreCase)
            : [];
        var fields = (request.Fields ?? []).Where(input => !taken.Contains(input.Name)).Select(input => (Input: input, Field: Field.Define(input.Name, input.Type, input.Sensitive))).ToList();
        foreach (var (input, field) in fields)
        {
            field.Validate(input.Value.Span);
        }

        SecretLimits.ValidateFields([.. fields.Select(item => (item.Field, item.Input.Value.Length))]);

        // Setting is a right of its own: a Secrets Writer has it without being able to read what was there.
        var vault = await RequireVaultAsync(request.Vault, caller, VaultRole.SecretsOfficer, cancellationToken, setting: true);
        var entry = await store.FindEntryAsync(vault.Id, Key(request.Name), cancellationToken);
        StoredValue value;
        var created = entry is null;
        if (entry is null)
        {
            value = new StoredValue { Id = Guid.NewGuid(), Kind = ValueKind.Secret, CreatedUtc = Now() };
            entry = new SecretEntry { Id = Guid.NewGuid(), VaultId = vault.Id, ValueId = value.Id, Name = request.Name, NameKey = Key(request.Name), CreatedUtc = Now() };
            store.Add(value);
            store.Add(entry);
        }
        else
        {
            value = (await store.GetValuesAsync([entry.ValueId], cancellationToken))[entry.ValueId];
            RequireKind(value, ValueKind.Secret, request.Name);
        }

        var description = request.Description;
        var contentType = request.ContentType;
        var keepDetails = request.KeepDetails;
        var keepSensitive = request.KeepSensitiveFields;
        if (!created && request.Merge)
        {
            var named = fields.Select(item => item.Field.Name).Concat(taken).ToHashSet(StringComparer.OrdinalIgnoreCase);
            foreach (var old in entry.Fields.Where(old => !named.Contains(old.Name)))
            {
                var stays = new FieldInput(old.Name, Encoding.UTF8.GetBytes(old.Value), old.Type);
                fields.Add((stays, Field.Define(old.Name, old.Type)));
            }

            var now = await store.FindVersionAsync(value.CurrentVersionId, cancellationToken);
            keepSensitive = [.. now!.Items.Where(item => item.Slot.StartsWith(FieldPrefix, StringComparison.Ordinal)).Select(item => item.Slot[FieldPrefix.Length..]).Where(name => !named.Contains(name))];
            description ??= entry.Description;
            contentType ??= value.ContentType;
            keepDetails = false;
            SecretLimits.ValidateValue(request.Value.Span, contentType);
            SecretLimits.ValidateFields([.. fields.Select(item => (item.Field, item.Input.Value.Length))]);
        }

        // The value and the sensitive fields belong to the version, under its data key.
        var versionId = Guid.NewGuid();
        var items = new Dictionary<string, ReadOnlyMemory<byte>>(StringComparer.Ordinal) { [ValueSlot] = request.Value };
        foreach (var (input, field) in fields.Where(item => item.Field.Sensitive))
        {
            items[FieldSlot(field.Name)] = input.Value;
        }

        // A new version that only changes the value carries the sensitive fields it was asked to keep. They are
        // moved from the old version to the new one inside the server: nobody reads them, so there is no audit row.
        var keptTypes = new Dictionary<string, FieldType?>(StringComparer.Ordinal);
        var kept = new List<SecretBytes>();
        if (!created && keepSensitive is { Count: > 0 } keep)
        {
            var current = await store.FindVersionAsync(value.CurrentVersionId, cancellationToken);
            var sealedCurrent = new SealedVersion(
                Blob.UnpackKey(current!.DataKeyId, current.DataKey),
                current.Items.ToDictionary(item => item.Slot, item => Blob.UnpackItem(item.Content), StringComparer.Ordinal));
            foreach (var slot in keep.Select(FieldSlot).Where(slot => !items.ContainsKey(slot) && sealedCurrent.Items.ContainsKey(slot)))
            {
                var bytes = keyRing.Open(new VersionAddress(value.Id, current.Id), sealedCurrent, slot);
                kept.Add(bytes);
                items[slot] = bytes.Reveal().ToArray();
                keptTypes[slot] = current.Items.First(item => item.Slot == slot).FieldType;
            }
        }

        var address = new VersionAddress(value.Id, versionId);
        var sealedVersion = keyRing.Seal(address, items);
        foreach (var bytes in kept)
        {
            bytes.Dispose();
        }

        var version = new StoredVersion
        {
            Id = versionId,
            ValueId = value.Id,
            Number = await store.LastVersionNumberAsync(value.Id, cancellationToken) + 1,
            CreatedUtc = Now(),
            CreatedBy = caller.Principal,
            DataKeyId = sealedVersion.Key.MasterKeyId,
            DataKey = Blob.Pack(sealedVersion.Key),
        };
        foreach (var (slot, item) in sealedVersion.Items)
        {
            var type = keptTypes.GetValueOrDefault(slot) ?? fields.FirstOrDefault(candidate => FieldSlot(candidate.Field.Name) == slot).Field?.Type;
            version.Items.Add(new VersionItem { Id = Guid.NewGuid(), VersionId = versionId, Slot = slot, FieldType = type, Content = Blob.Pack(item) });
        }

        store.Add(version);
        value.CurrentVersionId = versionId;
        value.ContentType = contentType;

        // The description is this name's own; the ordinary fields belong to the value, like the sensitive ones, and
        // every name of it gets them. Plain columns, replaced whole unless kept.
        if (created || !keepDetails)
        {
            entry.Description = NullIfEmpty(description);
            await ReplaceFieldsAsync(entry, [.. fields.Where(item => !item.Field.Sensitive)], cancellationToken);
        }

        store.Add(Audit(created ? "secret.created" : "secret.version.set", caller, vault, entry, versionId));
        await store.SaveAsync(cancellationToken);
        return version.Number;
    }

    /// <summary>Reads the value, or one sensitive field with <paramref name="slot"/>. This is the audited read.</summary>
    public async Task<SecretBytes> ReadAsync(string vaultName, string name, Caller caller, string slot = ValueSlot, int? number = null, CancellationToken cancellationToken = default) =>
        (await RevealAsync(vaultName, name, caller, slot, number, cancellationToken)).Bytes;

    /// <summary>The audited read, with the version it came from: the current one, or an earlier one by its number.</summary>
    public async Task<Revealed> RevealAsync(string vaultName, string name, Caller caller, string slot = ValueSlot, int? number = null, CancellationToken cancellationToken = default)
    {
        var asked = number;
        var vault = await RequireVaultAsync(vaultName, caller, CertificateParts.IsPublicSlot(slot) ? VaultRole.Reader : VaultRole.SecretsUser, cancellationToken);
        var entry = await RequireEntryAsync(vault, name, cancellationToken);
        if (!entry.Enabled)
        {
            throw new DomainException("secret.disabled", $"'{name}' is disabled.");
        }

        var value = (await store.GetValuesAsync([entry.ValueId], cancellationToken))[entry.ValueId];
        var version = asked is { } wanted
            ? (await store.ListVersionsAsync(value.Id, cancellationToken)).FirstOrDefault(candidate => candidate.Number == wanted)
                ?? throw new DomainException("secret.version.not_found", $"'{name}' has no version {wanted.ToString(System.Globalization.CultureInfo.InvariantCulture)}.")
            : await store.FindVersionAsync(value.CurrentVersionId, cancellationToken)
                ?? throw new DomainException("secret.version.missing", $"'{name}' has no current version.");
        var sealedVersion = new SealedVersion(
            Blob.UnpackKey(version.DataKeyId, version.DataKey),
            version.Items.ToDictionary(item => item.Slot, item => Blob.UnpackItem(item.Content), StringComparer.Ordinal));
        if (!sealedVersion.Items.ContainsKey(slot))
        {
            throw new DomainException("secret.slot.not_found", $"'{name}' has no '{slot}'.");
        }

        // Reading what a secret used to be is still reading a secret; the row says which version it was.
        var earlier = version.Id == value.CurrentVersionId ? null : $"version {version.Number.ToString(System.Globalization.CultureInfo.InvariantCulture)}, not the current one";

        var bytes = keyRing.Open(new VersionAddress(value.Id, version.Id), sealedVersion, slot);
        if (CertificateParts.IsPublicSlot(slot))
        {
            // The certificate and its chain are public: reading them is not a value read and leaves no row.
            return new Revealed(bytes, version.Id, version.Number);
        }

        try
        {
            // Written before the value is handed over: a read that cannot be recorded does not happen.
            store.Add(Audit("secret.value.read", caller, vault, entry, version.Id, slot, earlier));
            await store.SaveAsync(cancellationToken);
            return new Revealed(bytes, version.Id, version.Number);
        }
        catch
        {
            bytes.Dispose();
            throw;
        }
    }

    /// <summary>
    /// Stores a certificate, or a renewal of it as a new version. Every part is checked first: all of them must be
    /// the same certificate, and what the certificate says about itself is recorded from the certificate.
    /// </summary>
    public async Task<int> ImportCertificateAsync(ImportCertificate request, Caller caller, CancellationToken cancellationToken = default)
    {
        Naming.Secret(request.Name);
        var facts = CertificateParts.Inspect(request.Parts);

        var vault = await RequireVaultAsync(request.Vault, caller, VaultRole.SecretsOfficer, cancellationToken, setting: true);
        var entry = await store.FindEntryAsync(vault.Id, Key(request.Name), cancellationToken);
        StoredValue value;
        var created = entry is null;
        if (entry is null)
        {
            value = new StoredValue { Id = Guid.NewGuid(), Kind = ValueKind.Certificate, CreatedUtc = Now() };
            entry = new SecretEntry { Id = Guid.NewGuid(), VaultId = vault.Id, ValueId = value.Id, Name = request.Name, NameKey = Key(request.Name), CreatedUtc = Now() };
            store.Add(value);
            store.Add(entry);
        }
        else
        {
            value = (await store.GetValuesAsync([entry.ValueId], cancellationToken))[entry.ValueId];
            RequireKind(value, ValueKind.Certificate, request.Name);
        }

        var versionId = Guid.NewGuid();
        var sealedVersion = keyRing.Seal(
            new VersionAddress(value.Id, versionId),
            request.Parts.ToDictionary(part => CertificateParts.Slot(part.Kind), part => part.Content, StringComparer.Ordinal));
        var version = new StoredVersion
        {
            Id = versionId,
            ValueId = value.Id,
            Number = await store.LastVersionNumberAsync(value.Id, cancellationToken) + 1,
            CreatedUtc = Now(),
            CreatedBy = caller.Principal,
            DataKeyId = sealedVersion.Key.MasterKeyId,
            DataKey = Blob.Pack(sealedVersion.Key),
        };
        foreach (var part in request.Parts)
        {
            var slot = CertificateParts.Slot(part.Kind);
            version.Items.Add(new VersionItem { Id = Guid.NewGuid(), VersionId = versionId, Slot = slot, FileName = Path.GetFileName(part.FileName), Content = Blob.Pack(sealedVersion.Items[slot]) });
        }

        store.Add(version);
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
            AlternativeNames = string.Join(NameSeparator, facts.AlternativeNames),
        });

        // The lifetime is the certificate's own, so it cannot be mistyped or forgotten.
        value.CurrentVersionId = versionId;
        value.NotBeforeUtc = facts.NotBeforeUtc;
        value.ExpiresUtc = facts.NotAfterUtc;
        entry.Description = NullIfEmpty(request.Description);

        store.Add(Audit(created ? "certificate.created" : "certificate.version.set", caller, vault, entry, versionId));
        await store.SaveAsync(cancellationToken);
        return version.Number;
    }

    /// <summary>Reads one part of a certificate. A private part is an audited value read; a public one is not.</summary>
    public async Task<RevealedPart> ReadPartAsync(string vaultName, string name, CertificatePartKind kind, Caller caller, int? number = null, CancellationToken cancellationToken = default)
    {
        var slot = CertificateParts.Slot(kind);
        var revealed = await RevealAsync(vaultName, name, caller, slot, number, cancellationToken);
        var version = await store.FindVersionAsync(revealed.VersionId, cancellationToken);
        return new RevealedPart(revealed, version!.Items.First(item => item.Slot == slot).FileName);
    }

    /// <summary>The vaults the caller has any role in. The rest do not exist as far as they can tell.</summary>
    public async Task<IReadOnlyList<VaultSummary>> ListVaultsAsync(Caller caller, CancellationToken cancellationToken = default)
    {
        var visible = await VisibleVaultsAsync(caller, cancellationToken);
        var folders = (await store.ListFoldersAsync(cancellationToken)).ToDictionary(folder => folder.Id, folder => folder.Name);
        return [.. (await store.ListVaultsAsync(cancellationToken))
            .Where(vault => visible.Contains(vault.Id))
            .Select(vault => new VaultSummary(vault.Name, vault.Description, vault.PurgeProtection, vault.CreatedUtc, vault.FolderId is { } folder ? folders.GetValueOrDefault(folder) : null))];
    }

    /// <summary>
    /// The newest audit rows first: of everything, of one vault, or of one secret in it. Rows carry names as they
    /// were at the time, so what happened to a secret before it was moved or renamed is found under its old name.
    /// </summary>
    /// <remarks>
    /// The whole trail is for administrators. A vault's own activity is for its Secrets Officers and up. With
    /// <paramref name="before"/>, the rows older than that row: the next page back, however long the trail is.
    /// </remarks>
    public async Task<IReadOnlyList<AuditEvent>> AuditAsync(int take, Caller caller, string? vault = null, string? secret = null, long? before = null, CancellationToken cancellationToken = default)
    {
        if (vault is null)
        {
            RequireInstanceAdmin(caller, "read the whole audit trail");
        }
        else if (!caller.IsInstanceAdmin)
        {
            await RequireVaultAsync(vault, caller, VaultRole.SecretsOfficer, cancellationToken);
        }

        // A vault's activity is everything that happened to it, under whatever name it had then. A name that is no
        // vault now (an administrator asking after a deleted or renamed one) finds the rows that carry that name.
        // The same for a secret: what happened to it under any name it had, in any vault it was moved from.
        var vaultId = vault is null ? null : (await store.FindVaultAsync(Key(vault), cancellationToken))?.Id;
        var entryId = vaultId is { } id && secret is not null ? (await store.FindEntryAsync(id, Key(secret), cancellationToken))?.Id : null;
        return await store.ListAuditAsync(Math.Clamp(take, 1, 500), vaultId, vault, entryId, secret, before, cancellationToken);
    }

    /// <summary>The secrets of a vault without one value read: names, ordinary fields, version ids.</summary>
    public async Task<IReadOnlyList<SecretSummary>> ListAsync(string vaultName, Caller caller, bool bin = false, CancellationToken cancellationToken = default)
    {
        var vault = await RequireVaultAsync(vaultName, caller, bin ? VaultRole.SecretsOfficer : VaultRole.Reader, cancellationToken);
        return await SummariseAsync(await store.ListEntriesAsync(vault.Id, bin, cancellationToken), caller, cancellationToken);
    }

    private async Task<IReadOnlyList<SecretSummary>> SummariseAsync(IReadOnlyList<SecretEntry> entries, Caller caller, CancellationToken cancellationToken)
    {
        var visible = await VisibleVaultsAsync(caller, cancellationToken);
        var vaults = (await store.ListVaultsAsync(cancellationToken)).ToDictionary(vault => vault.Id);
        var values = await store.GetValuesAsync([.. entries.Select(entry => entry.ValueId).Distinct()], cancellationToken);
        var versions = await store.GetVersionsAsync([.. values.Values.Select(value => value.CurrentVersionId)], cancellationToken);
        var certificates = await store.GetCertificatesAsync([.. versions.Keys], cancellationToken);
        var names = (await store.ListEntriesOfValuesAsync([.. values.Keys], cancellationToken)).Where(entry => !entry.InBin).ToLookup(entry => entry.ValueId);

        return [.. entries.OrderBy(entry => vaults[entry.VaultId].NameKey, StringComparer.Ordinal).ThenBy(entry => entry.NameKey, StringComparer.Ordinal).Select(entry =>
        {
            var value = values[entry.ValueId];
            var version = versions[value.CurrentVersionId];
            certificates.TryGetValue(version.Id, out var certificate);
            return new SecretSummary(
                entry.Id,
                entry.Name,
                value.Kind,
                entry.Enabled,
                entry.Description,
                value.ContentType,
                version.Id,
                version.Number,
                version.CreatedUtc,
                entry.Fields.ToDictionary(field => field.Name, field => field.Value, StringComparer.Ordinal),
                [.. version.Items.Where(item => item.Slot.StartsWith(FieldPrefix, StringComparison.Ordinal)).Select(item => item.Slot[FieldPrefix.Length..]).Order(StringComparer.Ordinal)],
                entry.DeletedUtc,
                entry.DeletedBy,
                certificate is null ? null : Facts(certificate),
                value.Kind != ValueKind.Certificate ? null : [.. version.Items
                    .Select(item => (Item: item, Kind: CertificateParts.ParseKind(item.Slot[PartPrefix.Length..])))
                    .OrderBy(part => part.Kind)
                    .Select(part => new PartSummary(CertificateParts.Name(part.Kind), part.Item.FileName, CertificateParts.IsPrivate(part.Kind)))],
                vaults[entry.VaultId].Name,
                [.. names[entry.ValueId].Where(other => other.Id != entry.Id && visible.Contains(other.VaultId)).Select(other => $"{vaults[other.VaultId].Name}/{other.Name}").Order(StringComparer.Ordinal)],
                entry.CopiedFrom,
                names[entry.ValueId].Count(other => other.Id != entry.Id && !visible.Contains(other.VaultId)));
        })];
    }

    /// <summary>Moves a secret to the bin of its vault. Nothing is destroyed.</summary>
    public async Task DeleteAsync(string vaultName, string name, Caller caller, CancellationToken cancellationToken = default)
    {
        var vault = await RequireVaultAsync(vaultName, caller, VaultRole.SecretsOfficer, cancellationToken);
        var entry = await RequireEntryAsync(vault, name, cancellationToken);
        entry.BinKey = entry.Id.ToString("N");
        entry.DeletedUtc = Now();
        entry.DeletedBy = caller.Principal;
        store.Add(Audit("secret.deleted", caller, vault, entry));
        await store.SaveAsync(cancellationToken);
    }

    /// <summary>Takes a secret out of the bin, under its own name or, when that has been taken since, another.</summary>
    public async Task RestoreAsync(string vaultName, Guid entryId, Caller caller, string? newName = null, CancellationToken cancellationToken = default)
    {
        var vault = await RequireVaultAsync(vaultName, caller, VaultRole.SecretsOfficer, cancellationToken);
        var entry = await store.FindBinnedEntryAsync(vault.Id, entryId, cancellationToken)
            ?? throw new DomainException("secret.not_in_bin", "That secret is not in the bin of this vault.");
        var name = Naming.Secret(newName ?? entry.Name);
        if (await store.FindEntryAsync(vault.Id, Key(name), cancellationToken) is not null)
        {
            throw new DomainException("secret.name.taken", $"'{name}' is in use; restore it under another name.");
        }

        entry.Name = name;
        entry.NameKey = Key(name);
        entry.BinKey = "";
        entry.DeletedUtc = null;
        entry.DeletedBy = null;
        store.Add(Audit("secret.restored", caller, vault, entry));
        await store.SaveAsync(cancellationToken);
    }

    private async Task<SecretEntry> RequireEntryAsync(Vault vault, string name, CancellationToken cancellationToken) =>
        await store.FindEntryAsync(vault.Id, Key(name), cancellationToken) ?? throw new DomainException("secret.not_found", $"There is no secret '{name}' in '{vault.Name}'.");

    /// <summary>
    /// Changes what describes a secret without touching its value: the description and the ordinary fields. No new
    /// version is made, because nothing secret changed.
    /// </summary>
    public async Task UpdateDetailsAsync(string vaultName, string name, string? description, IReadOnlyList<FieldInput> fields, Caller caller, CancellationToken cancellationToken = default)
    {
        var defined = fields.Select(input => (Input: input, Field: Field.Define(input.Name, input.Type, input.Sensitive))).ToList();
        if (defined.Any(item => item.Field.Sensitive))
        {
            throw new DomainException("field.sensitive.needs_version", "A sensitive field belongs to a version: set it with a new version.");
        }

        foreach (var (input, field) in defined)
        {
            field.Validate(input.Value.Span);
        }

        SecretLimits.ValidateFields([.. defined.Select(item => (item.Field, item.Input.Value.Length))]);
        var vault = await RequireVaultAsync(vaultName, caller, VaultRole.SecretsOfficer, cancellationToken);
        var entry = await RequireEntryAsync(vault, name, cancellationToken);
        entry.Description = NullIfEmpty(description);
        await ReplaceFieldsAsync(entry, defined, cancellationToken);
        store.Add(Audit("secret.details.changed", caller, vault, entry));
        await store.SaveAsync(cancellationToken);
    }

    /// <summary>
    /// Sets the ordinary fields of a value: on this name and on every other name of it, linked or in a bin, so a
    /// user name changes in one place, like the password beside it. The description is not touched.
    /// </summary>
    private async Task ReplaceFieldsAsync(SecretEntry entry, IReadOnlyList<(FieldInput Input, Field Field)> fields, CancellationToken cancellationToken)
    {
        var names = (await store.ListEntriesOfValuesAsync([entry.ValueId], cancellationToken)).Append(entry).DistinctBy(name => name.Id);
        var wanted = fields.Select(item => (item.Field.Name, item.Field.Type, Value: Encoding.UTF8.GetString(item.Input.Value.Span))).ToList();
        foreach (var name in names)
        {
            SetFields(name, wanted);
        }
    }

    private void SetFields(SecretEntry entry, IReadOnlyList<(string Name, FieldType Type, string Value)> fields)
    {
        foreach (var old in entry.Fields.ToList())
        {
            entry.Fields.Remove(old);
            store.Remove(old);
        }

        foreach (var (name, type, value) in fields)
        {
            entry.Fields.Add(new EntryField { Id = Guid.NewGuid(), EntryId = entry.Id, Name = name, Type = type, Value = value });
        }
    }

    private static string? NullIfEmpty(string? text) => string.IsNullOrEmpty(text) ? null : text;

    private AuditEvent Audit(string code, Caller caller, Vault vault, SecretEntry? entry = null, Guid? versionId = null, string? slot = null, string? detail = null) => new()
    {
        AtUtc = Now(),
        Code = code,
        Severity = AuditSeverity.Info,
        Principal = caller.Principal,
        Vault = vault.Name,
        VaultId = vault.Id,
        Secret = entry?.Name,
        EntryId = entry?.Id,
        VersionId = versionId,
        Slot = slot,
        Address = caller.Address,
        Via = caller.Via,
        Detail = detail,
    };

    private DateTime Now() => clock.GetUtcNow().UtcDateTime;

    private static string Key(string name) => name.ToLowerInvariant();

    private const string FieldPrefix = "field:";
    private const string PartPrefix = "part:";
    private const char NameSeparator = (char)10;

    private static string FieldSlot(string name) => FieldPrefix + name;

    private static void RequireKind(StoredValue value, ValueKind kind, string name)
    {
        if (value.Kind != kind)
        {
            throw new DomainException("secret.kind.mismatch", $"'{name}' is a {value.Kind.ToString().ToLowerInvariant()}, not a {kind.ToString().ToLowerInvariant()}.");
        }
    }

    private static CertificateFacts Facts(CertificateRecord record) => new(
        record.Subject,
        record.Issuer,
        record.Serial,
        record.Thumbprint,
        record.Sha1Thumbprint,
        record.NotBeforeUtc,
        record.NotAfterUtc,
        record.AlternativeNames.Length == 0 ? [] : record.AlternativeNames.Split(NameSeparator));
}

/// <summary>How the key ring's records are laid out in a single column: nonce, tag, ciphertext.</summary>
internal static class Blob
{
    private const int NonceBytes = 12;
    private const int TagBytes = 16;

    public static byte[] Pack(SealedItem item) => [.. item.Nonce, .. item.Tag, .. item.Ciphertext];

    public static byte[] Pack(WrappedKey key) => [.. key.Nonce, .. key.Tag, .. key.Ciphertext];

    public static SealedItem UnpackItem(byte[] content) =>
        new(content[..NonceBytes], content[(NonceBytes + TagBytes)..], content[NonceBytes..(NonceBytes + TagBytes)]);

    public static WrappedKey UnpackKey(string masterKeyId, byte[] content) =>
        new(masterKeyId, content[..NonceBytes], content[(NonceBytes + TagBytes)..], content[NonceBytes..(NonceBytes + TagBytes)]);
}
