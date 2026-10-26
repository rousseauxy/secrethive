namespace SecretHive.Domain.Entities;

/// <summary>The things a role is made of. Every check asks for one of these, never for a place on a ladder.</summary>
[Flags]
public enum VaultRights
{
    None = 0,

    /// <summary>What exists: names, descriptions, ordinary fields, versions, the public half of a certificate.</summary>
    See = 1,

    /// <summary>Values, sensitive fields, the private parts of a certificate.</summary>
    Read = 2,

    /// <summary>A value as a new secret or a new version; a certificate or its renewal.</summary>
    Set = 4,

    /// <summary>Everything else about a secret: delete, restore, rename, go back, copy, move; the vault's activity.</summary>
    Change = 8,

    /// <summary>Who has which role, links to other vaults, purging.</summary>
    Manage = 16,
}

public static class VaultRoles
{
    /// <summary>In the order a list shows them: from the least to the most.</summary>
    public static IReadOnlyList<VaultRole> All { get; } = [VaultRole.Reader, VaultRole.SecretsWriter, VaultRole.SecretsUser, VaultRole.SecretsOfficer, VaultRole.VaultAdmin];

    /// <summary>Where a role stands in that order, for sorting a list; not for deciding anything.</summary>
    public static int Place(VaultRole role)
    {
        for (var index = 0; index < All.Count; index++)
        {
            if (All[index] == role)
            {
                return index;
            }
        }

        return -1;
    }

    public static VaultRights Rights(this VaultRole role) => role switch
    {
        VaultRole.Reader => VaultRights.See,
        VaultRole.SecretsWriter => VaultRights.See | VaultRights.Set,
        VaultRole.SecretsUser => VaultRights.See | VaultRights.Read,
        VaultRole.SecretsOfficer => VaultRights.See | VaultRights.Read | VaultRights.Set | VaultRights.Change,
        VaultRole.VaultAdmin => VaultRights.See | VaultRights.Read | VaultRights.Set | VaultRights.Change | VaultRights.Manage,
        _ => VaultRights.None,
    };

    /// <summary>The one right a use case asks for when it names a role of the ladder.</summary>
    public static VaultRights Needs(VaultRole ladder) => ladder switch
    {
        VaultRole.Reader => VaultRights.See,
        VaultRole.SecretsUser => VaultRights.Read,
        VaultRole.SecretsOfficer => VaultRights.Change,
        VaultRole.VaultAdmin => VaultRights.Manage,
        _ => throw new ArgumentOutOfRangeException(nameof(ladder), "Ask for a role of the ladder, or for the right to set."),
    };

    /// <summary>
    /// The role that says best what a set of rights amounts to. Someone who reads through one assignment and sets
    /// through another is shown as a Secrets User: the name says what they can read, which is what matters most.
    /// </summary>
    public static VaultRole Named(VaultRights rights) =>
        rights.HasFlag(VaultRights.Manage) ? VaultRole.VaultAdmin
        : rights.HasFlag(VaultRights.Change) ? VaultRole.SecretsOfficer
        : rights.HasFlag(VaultRights.Read) ? VaultRole.SecretsUser
        : rights.HasFlag(VaultRights.Set) ? VaultRole.SecretsWriter
        : VaultRole.Reader;
}

/// <summary>
/// What a principal may do in one vault. Four roles are a ladder, each including the ones before it. Reading a
/// value is a role of its own, never implied by being able to see that a secret exists; and one role, Secrets
/// Writer, stands beside the ladder: it sets values and reads none. What a role may do is in <see cref="VaultRoles"/>.
/// </summary>
public enum VaultRole
{
    /// <summary>
    /// Sees what a Reader sees and sets values: a new secret, a new version, a certificate or its renewal. Never
    /// reads a value, changes nothing else. For a job that rotates. Its number is below every other on purpose:
    /// a comparison that forgets this role refuses.
    /// </summary>
    SecretsWriter = -1,

    /// <summary>Sees what exists: names, descriptions, ordinary fields, versions, the public half of a certificate. Never a value.</summary>
    Reader = 1,

    /// <summary>Reads values, sensitive fields and the private parts of certificates. Every such read is on record.</summary>
    SecretsUser = 2,

    /// <summary>Creates, changes, deletes and restores secrets and certificates; copies and moves them; sees the vault's activity.</summary>
    SecretsOfficer = 3,

    /// <summary>Decides who has which role, links secrets to other vaults, purges, and switches purge protection on.</summary>
    VaultAdmin = 4,
}

/// <summary>A named set of accounts, so a role is given once to a team instead of to each of its people.</summary>
public sealed class Group
{
    public int Key { get; set; }

    public required string Name { get; set; }

    /// <summary>Lower-cased, for the unique index and for look-ups.</summary>
    public required string NameLower { get; set; }

    public string Description { get; set; } = "";

    public DateTime CreatedUtc { get; set; }
}

public sealed class GroupMember
{
    public int Key { get; set; }

    public int GroupKey { get; set; }

    public int UserKey { get; set; }

    /// <summary><c>manual</c>, or the sign-in provider that put this account in the group. A provider refresh replaces only its own rows.</summary>
    public string Source { get; set; } = "manual";

    /// <summary>
    /// Null for a member an administrator added. Otherwise the provider whose groups claim made them a member: a
    /// sign-in with that provider replaces its own rows and leaves every other row alone.
    /// </summary>
    public int? ProviderKey { get; set; }
}

/// <summary>One role in one vault, held by an account or by a group. Exactly one of the two is set.</summary>
public sealed class VaultAssignment
{
    public int Key { get; set; }

    public Guid VaultId { get; set; }

    public int? UserKey { get; set; }

    public int? GroupKey { get; set; }

    public VaultRole Role { get; set; }

    public DateTime GrantedUtc { get; set; }

    public string GrantedBy { get; set; } = "";
}

/// <summary>
/// A vault, or a secret in it, that one account keeps at hand on its home page. Only that account sees it, and a pin
/// shows nothing the account could not see anyway: one on something it no longer may see is left out.
/// </summary>
public sealed class Pin
{
    public int Key { get; set; }

    public int UserKey { get; set; }

    public Guid VaultId { get; set; }

    /// <summary>The secret, or null for the vault itself. No foreign key: a pin of a deleted secret is simply not shown.</summary>
    public Guid? EntryId { get; set; }

    public DateTime CreatedUtc { get; set; }
}

/// <summary>
/// One role on one folder, held by an account or by a group: it counts in every vault beneath the folder, at any
/// depth, on top of what is given in the vault itself. Exactly one of account and group is set.
/// </summary>
public sealed class FolderAssignment
{
    public int Key { get; set; }

    public Guid FolderId { get; set; }

    public int? UserKey { get; set; }

    public int? GroupKey { get; set; }

    public VaultRole Role { get; set; }

    public DateTime GrantedUtc { get; set; }

    public string GrantedBy { get; set; } = "";
}

/// <summary>
/// A named list of address ranges, defined once for the instance: <c>tailnet</c>, <c>lan-devops</c>. Vaults and
/// keys list groups, so changing a group changes every vault and key that lists it, at once.
/// </summary>
public sealed class NetworkGroup
{
    public int Key { get; set; }

    public required string Name { get; set; }

    /// <summary>Lower-cased, for the unique index and for look-ups.</summary>
    public required string NameLower { get; set; }

    public string Description { get; set; } = "";

    /// <summary>Canonical ranges, one per line.</summary>
    public string Ranges { get; set; } = "";

    public DateTime CreatedUtc { get; set; }

    public IReadOnlyList<string> RangeList() => Ranges.Split('\n', StringSplitOptions.RemoveEmptyEntries);
}

/// <summary>
/// One line of the list of networks a vault or a key may be used from: a group, or a literal range. Exactly one of
/// vault and key is set, and exactly one of group and range. No lines at all means "from anywhere".
/// </summary>
public sealed class AllowedNetwork
{
    public int Key { get; set; }

    public Guid? VaultId { get; set; }

    public int? ApiKeyKey { get; set; }

    public int? GroupKey { get; set; }

    public string? Range { get; set; }
}

/// <summary>
/// A key a tool signs in with. It belongs to one identity and acts as that identity, never as more: optionally
/// narrowed to one vault and capped at a role. Only a hash is stored; the key itself is shown once, when it is made.
/// </summary>
public sealed class ApiKey
{
    public int Key { get; set; }

    public int UserKey { get; set; }

    /// <summary>What the key is for, in its owner's words.</summary>
    public string Label { get; set; } = "";

    /// <summary>The first characters of the key: enough to tell keys apart in a list and a log, useless for signing in.</summary>
    public required string Prefix { get; set; }

    /// <summary>SHA-256 of the whole key, in hexadecimal.</summary>
    public required string Hash { get; set; }

    /// <summary>When set, the key works in this vault only.</summary>
    public Guid? VaultId { get; set; }

    /// <summary>When set, the key never acts above this role, whatever its owner holds.</summary>
    public VaultRole? MaxRole { get; set; }

    public DateTime CreatedUtc { get; set; }

    /// <summary>When the key ends by itself, or null for a key that works until it is revoked.</summary>
    public DateTime? ExpiresUtc { get; set; }

    public DateTime? RevokedUtc { get; set; }

    public DateTime? LastUsedUtc { get; set; }

    public string? LastUsedAddress { get; set; }
}
