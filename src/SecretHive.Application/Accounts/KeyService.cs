using System.Security.Cryptography;
using System.Text;
using SecretHive.Application.Ports;
using SecretHive.Application.Secrets;
using SecretHive.Domain;
using SecretHive.Domain.Entities;

namespace SecretHive.Application.Accounts;

public interface IKeyStore
{
    Task<ApiKey?> FindAsync(int key, CancellationToken cancellationToken);

    Task<ApiKey?> FindByPrefixAsync(string prefix, CancellationToken cancellationToken);

    Task<IReadOnlyList<ApiKey>> ListForUserAsync(int userKey, CancellationToken cancellationToken);

    Task AddAsync(ApiKey key, CancellationToken cancellationToken);

    Task RevokeAsync(int key, DateTime atUtc, CancellationToken cancellationToken);

    Task SetMaxRoleAsync(int key, VaultRole? maxRole, CancellationToken cancellationToken);

    Task TouchAsync(int key, DateTime atUtc, string? address, CancellationToken cancellationToken);
}

/// <summary>A key as its owner sees it in a list. Never the key itself.</summary>
public sealed record KeySummary(int Key, string Label, string Prefix, string? Vault, VaultRole? MaxRole, DateTime CreatedUtc, DateTime? ExpiresUtc, DateTime? RevokedUtc, DateTime? LastUsedUtc, string? LastUsedAddress)
{
    /// <summary>The networks the key may be used from; empty when it is not limited.</summary>
    public IReadOnlyList<NetworkLine> Networks { get; init; } = [];

    public bool IsActive(DateTime nowUtc) => RevokedUtc is null && (ExpiresUtc is null || ExpiresUtc > nowUtc);
}

/// <summary>Who a presented key turned out to be.</summary>
public sealed record KeyIdentity(User Owner, ApiKey Key);

/// <summary>
/// Keys for tools. Each belongs to one identity and is audited under it; two jobs never share one. A key is
/// random, stored as a hash, shown once, and ends on a date unless it was made without one, which is said aloud
/// in the audit trail. An identity may hold two that work at the same time,
/// so a rotation is: make the new one, roll it out, revoke the old one.
/// </summary>
public sealed class KeyService(IKeyStore keys, IUserStore users, ISecretStore store, AuditWriter audit, TimeProvider clock, IAccessStore access)
{
    public const string Marker = "shv_";
    public const int MaxActiveKeys = 2;
    public const int DefaultDays = 90;
    public const int MaxDays = 366;

    private const int PrefixLength = 8;

    /// <summary>
    /// Makes a key and returns it. This is the only time it exists outside its owner's hands. Without a number of
    /// days the key has no end: it works until someone revokes it, and making it is a security event.
    /// </summary>
    public async Task<(KeySummary Key, string Secret)> CreateAsync(Caller caller, int ownerKey, string label, int? days, string? vaultName, VaultRole? maxRole, CancellationToken cancellationToken = default)
    {
        var owner = await RequireOwnerAsync(caller, ownerKey, cancellationToken);
        if (string.IsNullOrWhiteSpace(label) || label.Trim().Length > 128)
        {
            throw new DomainException("key.label.invalid", "Say what the key is for, in at most 128 characters.");
        }

        if (days is < 1 or > MaxDays)
        {
            throw new DomainException("key.expiry.invalid", $"A key lasts between 1 and {MaxDays} days.");
        }

        RequireRole(maxRole);
        var now = clock.GetUtcNow().UtcDateTime;
        if ((await keys.ListForUserAsync(ownerKey, cancellationToken)).Count(existing => existing.RevokedUtc is null && (existing.ExpiresUtc is null || existing.ExpiresUtc > now)) >= MaxActiveKeys)
        {
            throw new DomainException("key.too_many", $"An identity holds at most {MaxActiveKeys} working keys: one in use and one being rolled out. Revoke one first.");
        }

        Vault? vault = null;
        if (!string.IsNullOrWhiteSpace(vaultName))
        {
            vault = await store.FindVaultAsync(vaultName.Trim().ToLowerInvariant(), cancellationToken)
                ?? throw new DomainException("vault.not_found", $"There is no vault '{vaultName}'.");
        }

        // 32 random bytes: nothing to guess, so a plain hash is all the storage needs.
        var prefix = Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(PrefixLength / 2));
        var secret = $"{Marker}{prefix}_{Base64Url(RandomNumberGenerator.GetBytes(32))}";
        var key = new ApiKey
        {
            UserKey = ownerKey,
            Label = label.Trim(),
            Prefix = prefix,
            Hash = HashOf(secret),
            VaultId = vault?.Id,
            MaxRole = maxRole,
            CreatedUtc = now,
            ExpiresUtc = days is { } lasts ? now.AddDays(lasts) : null,
        };
        await keys.AddAsync(key, cancellationToken);
        await audit.RecordAsync("key.created", caller, $"{owner.UserName} {prefix} \"{key.Label}\"{(vault is null ? "" : " vault=" + vault.Name)}{(maxRole is null ? "" : " max=" + SecretService.RoleName(maxRole.Value))} {(days is null ? "no end date" : "days=" + days.Value.ToString(System.Globalization.CultureInfo.InvariantCulture))}", days is null ? AuditSeverity.Security : AuditSeverity.Notice, cancellationToken: cancellationToken);
        return (Summary(key, vault?.Name), secret);
    }

    public async Task<IReadOnlyList<KeySummary>> ListAsync(Caller caller, int ownerKey, CancellationToken cancellationToken = default)
    {
        await RequireOwnerAsync(caller, ownerKey, cancellationToken);
        var vaults = (await store.ListVaultsAsync(cancellationToken)).ToDictionary(vault => vault.Id, vault => vault.Name);
        var result = new List<KeySummary>();
        foreach (var key in (await keys.ListForUserAsync(ownerKey, cancellationToken)).OrderByDescending(key => key.CreatedUtc))
        {
            result.Add(Summary(key, key.VaultId is { } id ? vaults.GetValueOrDefault(id, "(deleted vault)") : null) with { Networks = await NetworkService.LinesAsync(access, null, key.Key, cancellationToken) });
        }

        return result;
    }

    /// <summary>Adds a network group or a literal range to the networks a key may be used from.</summary>
    public async Task AllowNetworkAsync(Caller caller, int keyId, int? groupKey, string? range, CancellationToken cancellationToken = default)
    {
        var key = await keys.FindAsync(keyId, cancellationToken) ?? throw new DomainException("key.not_found", "That key does not exist.");
        var owner = await RequireOwnerAsync(caller, key.UserKey, cancellationToken);
        var (line, label) = await NetworkService.NewLineAsync(access, null, key.Key, groupKey, range, cancellationToken);
        if (!await access.AddAllowedNetworkAsync(line, cancellationToken))
        {
            throw new DomainException("network.line.exists", "That network is already listed.");
        }

        await audit.RecordAsync("key.network.added", caller, $"{owner.UserName} {key.Prefix} + {label}", AuditSeverity.Notice, cancellationToken: cancellationToken);
    }

    public async Task DisallowNetworkAsync(Caller caller, int keyId, int lineKey, CancellationToken cancellationToken = default)
    {
        var key = await keys.FindAsync(keyId, cancellationToken) ?? throw new DomainException("key.not_found", "That key does not exist.");
        var owner = await RequireOwnerAsync(caller, key.UserKey, cancellationToken);
        var lines = await NetworkService.LinesAsync(access, null, key.Key, cancellationToken);
        var line = lines.FirstOrDefault(candidate => candidate.Key == lineKey) ?? throw new DomainException("network.line.not_found", "That network is not listed.");
        await access.RemoveAllowedNetworkAsync(lineKey, null, key.Key, cancellationToken);

        // Taking the last line away lets the key work from every address again.
        await audit.RecordAsync("key.network.removed", caller, $"{owner.UserName} {key.Prefix} - {line.Label}{(lines.Count == 1 ? " (no longer limited to any network)" : "")}", lines.Count == 1 ? AuditSeverity.Security : AuditSeverity.Notice, cancellationToken: cancellationToken);
    }

    /// <summary>
    /// Changes the highest role a working key acts with: another role, or none, so that it follows its owner's.
    /// Whoever may do this may make a new key with any limit, so it gives nobody more than they had; it saves
    /// rolling a new key out. Widening is what a stolen key would want, so that is a security event.
    /// </summary>
    public async Task SetMaxRoleAsync(Caller caller, int keyId, VaultRole? maxRole, CancellationToken cancellationToken = default)
    {
        var key = await keys.FindAsync(keyId, cancellationToken) ?? throw new DomainException("key.not_found", "That key does not exist.");
        var owner = await RequireOwnerAsync(caller, key.UserKey, cancellationToken);
        if (key.RevokedUtc is not null || key.ExpiresUtc <= clock.GetUtcNow().UtcDateTime)
        {
            throw new DomainException("key.ended", "That key has ended; its limit can no longer be changed.");
        }

        RequireRole(maxRole);
        if (key.MaxRole == maxRole)
        {
            return;
        }

        await keys.SetMaxRoleAsync(keyId, maxRole, cancellationToken);

        // Wider is anything the key may do now and could not before: from Reader to Secrets Writer as much as from
        // Secrets User to Secrets Officer.
        var widened = maxRole is null || (key.MaxRole is { } was && (maxRole.Value.Rights() & ~was.Rights()) != VaultRights.None);
        await audit.RecordAsync(
            "key.limit.changed",
            caller,
            $"{owner.UserName} {key.Prefix} \"{key.Label}\" {Limit(key.MaxRole)} -> {Limit(maxRole)}",
            widened ? AuditSeverity.Security : AuditSeverity.Notice,
            cancellationToken: cancellationToken);
    }

    private static void RequireRole(VaultRole? maxRole)
    {
        if (maxRole is { } role && role.Rights() == VaultRights.None)
        {
            throw new DomainException("key.limit.invalid", "That is not a role.");
        }
    }

    private static string Limit(VaultRole? role) => role is { } max ? "at most " + SecretService.RoleName(max) : "its owner's role";

    /// <summary>Ends a key now. The record stays, so the trail still says whose it was.</summary>
    public async Task RevokeAsync(Caller caller, int keyId, CancellationToken cancellationToken = default)
    {
        var key = await keys.FindAsync(keyId, cancellationToken) ?? throw new DomainException("key.not_found", "That key does not exist.");
        var owner = await RequireOwnerAsync(caller, key.UserKey, cancellationToken);
        if (key.RevokedUtc is null)
        {
            await keys.RevokeAsync(keyId, clock.GetUtcNow().UtcDateTime, cancellationToken);
            await audit.RecordAsync("key.revoked", caller, $"{owner.UserName} {key.Prefix} \"{key.Label}\"", AuditSeverity.Notice, cancellationToken: cancellationToken);
        }
    }

    /// <summary>
    /// Who a presented key is, or null when it is no credential. A key that is known but revoked, expired or whose
    /// owner is disabled is refused on record: someone is still using it.
    /// </summary>
    public async Task<KeyIdentity?> AuthenticateAsync(string presented, string? address, CancellationToken cancellationToken = default)
    {
        if (!TryPrefix(presented, out var prefix) || await keys.FindByPrefixAsync(prefix, cancellationToken) is not { } key)
        {
            return null;
        }

        if (!CryptographicOperations.FixedTimeEquals(Encoding.ASCII.GetBytes(HashOf(presented)), Encoding.ASCII.GetBytes(key.Hash)))
        {
            return null;
        }

        var now = clock.GetUtcNow().UtcDateTime;
        var owner = await users.FindAsync(key.UserKey, cancellationToken);
        var reason = owner is null ? "owner gone" : owner.IsDisabled ? "owner disabled" : key.RevokedUtc is not null ? "revoked" : key.ExpiresUtc <= now ? "expired" : null;
        if (reason is not null)
        {
            await audit.RecordAsync("key.refused", new Caller(owner?.UserName ?? "unknown", address), $"{key.Prefix} \"{key.Label}\" {reason}", AuditSeverity.Security, cancellationToken: cancellationToken);
            return null;
        }

        // A good key in the wrong place: exactly what a stolen key looks like.
        var ranges = await access.ResolveAllowedRangesAsync(null, key.Key, cancellationToken);
        if (ranges.Count > 0 && !Networks.Contains(ranges, address))
        {
            await audit.RecordAsync("access.network.refused", new Caller(owner!.UserName, address), $"key {key.Prefix} \"{key.Label}\" outside its networks", AuditSeverity.Security, cancellationToken: cancellationToken);
            return null;
        }

        // When and from where it was last used is what says an old key is safe to revoke. Once a minute is enough.
        if (key.LastUsedUtc is null || now - key.LastUsedUtc > TimeSpan.FromMinutes(1) || key.LastUsedAddress != address)
        {
            await keys.TouchAsync(key.Key, now, address, cancellationToken);
        }

        return new KeyIdentity(owner!, key);
    }

    public static bool LooksLikeKey(string? presented) => presented is not null && presented.StartsWith(Marker, StringComparison.Ordinal);

    /// <summary>Your own keys, or a service identity's when you are an administrator. Never another person's.</summary>
    private async Task<User> RequireOwnerAsync(Caller caller, int ownerKey, CancellationToken cancellationToken)
    {
        var owner = await users.FindAsync(ownerKey, cancellationToken) ?? throw new DomainException("user.not_found", "That identity does not exist.");
        if (caller.UserKey == ownerKey && caller.KeyId is null)
        {
            return owner;
        }

        // The keys of a service identity that is itself an admin are a super admin's to make and end: an admin, or that
        // identity's own key, could otherwise keep the role alive by making the next key.
        if (owner.IsService && owner.Role >= UserRole.Admin)
        {
            if (caller.Unrestricted || (caller.Role == UserRole.SuperAdmin && caller.KeyId is null))
            {
                return owner;
            }

            throw new DomainException("access.denied", "The keys of a service identity that is an admin are managed by a super admin.");
        }

        if (caller.IsInstanceAdmin && owner.IsService)
        {
            return owner;
        }

        throw new DomainException("access.denied", "A key is managed by the identity it belongs to, or by an administrator when that identity is a service.");
    }

    private static bool TryPrefix(string presented, out string prefix)
    {
        prefix = "";
        if (!LooksLikeKey(presented) || presented.Length < Marker.Length + PrefixLength + 2 || presented[Marker.Length + PrefixLength] != '_')
        {
            return false;
        }

        prefix = presented.Substring(Marker.Length, PrefixLength);
        return true;
    }

    private static string HashOf(string secret) => Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(secret)));

    private static string Base64Url(byte[] bytes) => Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private static KeySummary Summary(ApiKey key, string? vault) =>
        new(key.Key, key.Label, key.Prefix, vault, key.MaxRole, key.CreatedUtc, key.ExpiresUtc, key.RevokedUtc, key.LastUsedUtc, key.LastUsedAddress);
}
