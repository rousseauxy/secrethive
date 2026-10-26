using System.Globalization;
using SecretHive.Application.Ports;
using SecretHive.Domain;
using SecretHive.Domain.Entities;

namespace SecretHive.Application.Secrets;

/// <summary>One version of a secret or a certificate, as a Reader may see it: when, by whom, and what it holds. Never a value.</summary>
public sealed record VersionInfo(
    int Number,
    Guid Id,
    DateTime CreatedUtc,
    string CreatedBy,
    bool Current,
    IReadOnlyList<string> Slots,
    string? CertificateThumbprint = null,
    DateTime? CertificateNotAfterUtc = null);

/// <summary>
/// The history of a secret. Every change makes a new version and the earlier ones stay, encrypted like the current
/// one. They can be listed by anyone who may see the secret, read by anyone who may read its value (each read on
/// record, naming the version), and made current again by anyone who may change it.
/// </summary>
public sealed partial class SecretService
{
    /// <summary>Newest first.</summary>
    public async Task<IReadOnlyList<VersionInfo>> ListVersionsAsync(string vaultName, string name, Caller caller, CancellationToken cancellationToken = default)
    {
        var vault = await RequireVaultAsync(vaultName, caller, VaultRole.Reader, cancellationToken);
        var entry = await RequireEntryAsync(vault, name, cancellationToken);
        var value = (await store.GetValuesAsync([entry.ValueId], cancellationToken))[entry.ValueId];
        var versions = await store.ListVersionsAsync(value.Id, cancellationToken);
        var certificates = await store.GetCertificatesAsync([.. versions.Select(version => version.Id)], cancellationToken);
        return [.. versions
            .OrderByDescending(version => version.Number)
            .Select(version => new VersionInfo(
                version.Number,
                version.Id,
                version.CreatedUtc,
                version.CreatedBy,
                version.Id == value.CurrentVersionId,
                [.. version.Items.Select(item => item.Slot).Order(StringComparer.Ordinal)],
                certificates.GetValueOrDefault(version.Id)?.Thumbprint,
                certificates.GetValueOrDefault(version.Id)?.NotAfterUtc))];
    }

    /// <summary>
    /// Makes an earlier version the current one again, as a new version with the same content: history only ever
    /// grows, and what was current in between stays in it. Where the secret is linked into other vaults they all
    /// follow, as with any new version. The description and the ordinary fields are not part of a version and stay
    /// as they are.
    /// </summary>
    /// <returns>The number of the new version.</returns>
    public async Task<int> RestoreVersionAsync(string vaultName, string name, int number, Caller caller, CancellationToken cancellationToken = default)
    {
        var vault = await RequireVaultAsync(vaultName, caller, VaultRole.SecretsOfficer, cancellationToken);
        var entry = await RequireEntryAsync(vault, name, cancellationToken);
        var value = (await store.GetValuesAsync([entry.ValueId], cancellationToken))[entry.ValueId];
        var source = (await store.ListVersionsAsync(value.Id, cancellationToken)).FirstOrDefault(version => version.Number == number)
            ?? throw new DomainException("secret.version.not_found", $"'{name}' has no version {number.ToString(CultureInfo.InvariantCulture)}.");
        if (source.Id == value.CurrentVersionId)
        {
            throw new DomainException("secret.version.current", $"Version {number.ToString(CultureInfo.InvariantCulture)} is the current one.");
        }

        // Each item is bound to the version it belongs to, so it is opened and sealed again for the new one. Nothing
        // leaves the server, and nothing is shown to anyone: this is not a read.
        var sealedSource = new SealedVersion(
            Blob.UnpackKey(source.DataKeyId, source.DataKey),
            source.Items.ToDictionary(item => item.Slot, item => Blob.UnpackItem(item.Content), StringComparer.Ordinal));
        var opened = new Dictionary<string, SecretBytes>(StringComparer.Ordinal);
        var versionId = Guid.NewGuid();
        SealedVersion sealedCopy;
        try
        {
            foreach (var item in source.Items)
            {
                opened[item.Slot] = keyRing.Open(new VersionAddress(value.Id, source.Id), sealedSource, item.Slot);
            }

            sealedCopy = keyRing.Seal(
                new VersionAddress(value.Id, versionId),
                opened.ToDictionary(pair => pair.Key, pair => (ReadOnlyMemory<byte>)pair.Value.Reveal().ToArray(), StringComparer.Ordinal));
        }
        finally
        {
            foreach (var bytes in opened.Values)
            {
                bytes.Dispose();
            }
        }

        var version = new StoredVersion
        {
            Id = versionId,
            ValueId = value.Id,
            Number = await store.LastVersionNumberAsync(value.Id, cancellationToken) + 1,
            CreatedUtc = Now(),
            CreatedBy = caller.Principal,
            DataKeyId = sealedCopy.Key.MasterKeyId,
            DataKey = Blob.Pack(sealedCopy.Key),
        };
        foreach (var item in source.Items)
        {
            version.Items.Add(new VersionItem { Id = Guid.NewGuid(), VersionId = versionId, Slot = item.Slot, FieldType = item.FieldType, FileName = item.FileName, Content = Blob.Pack(sealedCopy.Items[item.Slot]) });
        }

        store.Add(version);
        if ((await store.GetCertificatesAsync([source.Id], cancellationToken)).GetValueOrDefault(source.Id) is { } facts)
        {
            // The certificate says the same about itself whichever version holds it; its lifetime is the value's again.
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
            value.NotBeforeUtc = facts.NotBeforeUtc;
            value.ExpiresUtc = facts.NotAfterUtc;
        }

        value.CurrentVersionId = versionId;
        var audit = Audit("secret.version.restored", caller, vault, entry, versionId, detail: $"version {version.Number.ToString(CultureInfo.InvariantCulture)} holds what version {number.ToString(CultureInfo.InvariantCulture)} held");
        audit.Severity = AuditSeverity.Notice;
        store.Add(audit);
        await store.SaveAsync(cancellationToken);
        return version.Number;
    }
}
