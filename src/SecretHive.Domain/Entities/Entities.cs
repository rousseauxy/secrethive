namespace SecretHive.Domain.Entities;

// What is stored. Values, sensitive fields and private certificate parts are held as ciphertext (byte arrays the
// key ring produced). Names, descriptions, ordinary fields, times and structure are plain columns, on purpose: they
// are what a report or a query needs, and "sensitive" is the one switch that takes something out of reach.

/// <summary>The unit of access. Holds names; the values those names point to do not belong to any one vault.</summary>
public sealed class Vault
{
    public Guid Id { get; set; }

    public string Name { get; set; } = "";

    /// <summary>The name lower-cased: lookups never depend on a database's collation.</summary>
    public string NameKey { get; set; } = "";

    public string? Description { get; set; }

    public bool PurgeProtection { get; set; }

    public DateTime CreatedUtc { get; set; }

    /// <summary>The folder the vault is in, or null at the top. A role given on that folder, or on one above it, counts here.</summary>
    public Guid? FolderId { get; set; }
}

/// <summary>
/// A folder of vaults and of other folders, the same tree for everyone. A role given on a folder counts in every
/// vault beneath it, worked out at each check and never copied, so moving a vault changes who reaches it at once.
/// Names are unique across all folders.
/// </summary>
public sealed class Folder
{
    public Guid Id { get; set; }

    public string Name { get; set; } = "";

    /// <summary>The name lower-cased: lookups never depend on a database's collation.</summary>
    public string NameKey { get; set; } = "";

    /// <summary>The folder this one is in, or null at the top.</summary>
    public Guid? ParentId { get; set; }

    public string? Description { get; set; }

    public DateTime CreatedUtc { get; set; }
}

/// <summary>
/// One name in one vault for a value. Several entries may point at the same value: that is a link, and none of
/// them is the original. What is the entry's own lives here; what is shared lives on the value.
/// </summary>
public sealed class SecretEntry
{
    public Guid Id { get; set; }

    public Guid VaultId { get; set; }

    public Guid ValueId { get; set; }

    public string Name { get; set; } = "";

    public string NameKey { get; set; } = "";

    /// <summary>
    /// Empty while the entry is live; the entry's own id once it is in the bin. Part of the unique index with the
    /// vault and the name, so a live name is unique, any number of deleted ones may share it, and neither database
    /// needs a filtered index to say so.
    /// </summary>
    public string BinKey { get; set; } = "";

    public bool Enabled { get; set; } = true;

    public string? Description { get; set; }

    public DateTime CreatedUtc { get; set; }

    public DateTime? DeletedUtc { get; set; }

    public string? DeletedBy { get; set; }

    /// <summary>Set on a copy, and on a name that was unlinked: <c>vault/name/version</c> of what it was made from.</summary>
    public string? CopiedFrom { get; set; }

#pragma warning disable CA2227 // EF Core fills the collection
    public List<EntryField> Fields { get; set; } = [];
#pragma warning restore CA2227

    public bool InBin => BinKey.Length > 0;
}

/// <summary>A field that is not sensitive: metadata of one entry, readable with the Reader role and with a query.</summary>
public sealed class EntryField
{
    public Guid Id { get; set; }

    public Guid EntryId { get; set; }

    public string Name { get; set; } = "";

    public FieldType Type { get; set; }

    public string Value { get; set; } = "";
}

public enum ValueKind
{
    Secret,
    Certificate,
}

/// <summary>What linked names share: the kind, the content type, the lifetime and the chain of versions.</summary>
public sealed class StoredValue
{
    public Guid Id { get; set; }

    public ValueKind Kind { get; set; }

    public string? ContentType { get; set; }

    public DateTime? NotBeforeUtc { get; set; }

    public DateTime? ExpiresUtc { get; set; }

    public Guid CurrentVersionId { get; set; }

    public DateTime CreatedUtc { get; set; }
}

/// <summary>Immutable once written. Its items are encrypted under its own data key.</summary>
public sealed class StoredVersion
{
    public Guid Id { get; set; }

    public Guid ValueId { get; set; }

    public int Number { get; set; }

    public DateTime CreatedUtc { get; set; }

    public string CreatedBy { get; set; } = "";

    public string DataKeyId { get; set; } = "";

    public byte[] DataKey { get; set; } = [];

#pragma warning disable CA2227 // EF Core fills the collection
    public List<VersionItem> Items { get; set; } = [];
#pragma warning restore CA2227
}

/// <summary>One encrypted item of a version: the value, a sensitive field, later a certificate part.</summary>
public sealed class VersionItem
{
    public Guid Id { get; set; }

    public Guid VersionId { get; set; }

    /// <summary><c>value</c>, <c>field:name</c> or <c>part:name</c>.</summary>
    public string Slot { get; set; } = "";

    /// <summary>Set for a sensitive field.</summary>
    public FieldType? FieldType { get; set; }

    /// <summary>The name a certificate part was supplied under, for handing it back as the same file.</summary>
    public string? FileName { get; set; }

    public byte[] Content { get; set; } = [];
}

public enum AuditSeverity
{
    Info,
    Notice,
    Security,
}

/// <summary>One line of the audit trail. Rows are only ever added. It names things and never holds a value.</summary>
public sealed class AuditEvent
{
    public long Id { get; set; }

    public DateTime AtUtc { get; set; }

    public string Code { get; set; } = "";

    public AuditSeverity Severity { get; set; }

    public string Principal { get; set; } = "";

    /// <summary>The vault's name when it happened. A vault can be renamed since; <see cref="VaultId"/> says which it was.</summary>
    public string? Vault { get; set; }

    /// <summary>
    /// The vault the row is about, by id, so its activity stays its own after a rename. Empty for a row about no
    /// vault, and for a row written before 0.18 about a vault that no longer exists.
    /// </summary>
    public Guid? VaultId { get; set; }

    /// <summary>The secret's name when it happened. It can be renamed or moved since; <see cref="EntryId"/> says which it was.</summary>
    public string? Secret { get; set; }

    /// <summary>
    /// The secret the row is about, by id, so its history stays its own after a rename or a move. Empty for a row
    /// about no secret, and for a row written before 0.20 that could not be traced to one.
    /// </summary>
    public Guid? EntryId { get; set; }

    public Guid? VersionId { get; set; }

    public string? Slot { get; set; }

    public string? Address { get; set; }

    /// <summary>How it arrived: <c>api</c>, <c>ui</c>, <c>cli</c>.</summary>
    public string? Via { get; set; }

    /// <summary>The other names an action touched, as <c>vault/name</c>. Names only.</summary>
    public string? Detail { get; set; }
}

/// <summary>A setting an administrator changes while the server runs.</summary>
public sealed class AppSetting
{
    public string Key { get; set; } = "";

    public string Value { get; set; } = "";
}

/// <summary>
/// What a certificate version says about itself. Readable in the database on purpose: it is public information from
/// the certificate, and expiry has to be something a query can find.
/// </summary>
public sealed class CertificateRecord
{
    public Guid VersionId { get; set; }

    public string Subject { get; set; } = "";

    public string Issuer { get; set; } = "";

    public string Serial { get; set; } = "";

    /// <summary>SHA-256 of the certificate.</summary>
    public string Thumbprint { get; set; } = "";

    /// <summary>SHA-1 of the certificate: what most tools still show as "the thumbprint".</summary>
    public string Sha1Thumbprint { get; set; } = "";

    public DateTime NotBeforeUtc { get; set; }

    public DateTime NotAfterUtc { get; set; }

    /// <summary>One name per line.</summary>
    public string AlternativeNames { get; set; } = "";
}
