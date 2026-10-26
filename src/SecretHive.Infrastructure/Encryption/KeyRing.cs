using System.Security.Cryptography;
using System.Text;
using SecretHive.Application.Ports;
using SecretHive.Domain;

namespace SecretHive.Infrastructure.Encryption;

/// <summary>
/// AES-256-GCM throughout, from the base library. What each ciphertext is for (which vault, secret, version and
/// slot) is authenticated with it, so material copied to another row, or a field swapped for the value, fails to
/// open instead of opening as the wrong thing.
/// </summary>
public sealed class KeyRing : IKeyRing, IDisposable
{
    private const int KeyBytes = 32;
    private const int NonceBytes = 12;
    private const int TagBytes = 16;
    private const string WrapPurpose = "secrethive/wrap/v1";

    private readonly Dictionary<string, byte[]> _wrappingKeys = new(StringComparer.Ordinal);

    /// <param name="current">The key new material is wrapped with.</param>
    /// <param name="retired">Earlier master keys, kept readable until everything is re-wrapped.</param>
    public KeyRing(MasterKey current, IEnumerable<MasterKey>? retired = null)
    {
        CurrentKeyId = current.Id;
        foreach (var key in (retired ?? []).Append(current))
        {
            _wrappingKeys[key.Id] = key.Derive(WrapPurpose);
        }
    }

    public string CurrentKeyId { get; }

    public SealedVersion Seal(VersionAddress address, IReadOnlyDictionary<string, ReadOnlyMemory<byte>> items)
    {
        var dataKey = RandomNumberGenerator.GetBytes(KeyBytes);
        try
        {
            var sealedItems = items.ToDictionary(
                item => item.Key,
                item => Encrypt(dataKey, item.Value.Span, ItemContext(address, item.Key)),
                StringComparer.Ordinal);
            return new SealedVersion(Wrap(dataKey, DataKeyContext(address)), sealedItems);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(dataKey);
        }
    }

    public SecretBytes Open(VersionAddress address, SealedVersion version, string slot)
    {
        if (!version.Items.TryGetValue(slot, out var item))
        {
            throw new KeyRingException($"This version has no '{slot}'.");
        }

        var dataKey = Unwrap(version.Key, DataKeyContext(address));
        try
        {
            return new SecretBytes(Decrypt(dataKey, item, ItemContext(address, slot)));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(dataKey);
        }
    }

    public SealedVersion Rewrap(VersionAddress address, SealedVersion version) =>
        version.Key.MasterKeyId == CurrentKeyId ? version : version with { Key = Rewrap(version.Key, DataKeyContext(address)) };

    public void Dispose()
    {
        foreach (var key in _wrappingKeys.Values)
        {
            CryptographicOperations.ZeroMemory(key);
        }
    }

    private WrappedKey Rewrap(WrappedKey wrapped, byte[] context)
    {
        var key = Unwrap(wrapped, context);
        try
        {
            return Wrap(key, context);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
        }
    }

    private WrappedKey Wrap(byte[] key, byte[] context)
    {
        var item = Encrypt(_wrappingKeys[CurrentKeyId], key, context);
        return new WrappedKey(CurrentKeyId, item.Nonce, item.Ciphertext, item.Tag);
    }

    private byte[] Unwrap(WrappedKey wrapped, byte[] context)
    {
        if (!_wrappingKeys.TryGetValue(wrapped.MasterKeyId, out var wrappingKey))
        {
            throw new KeyRingException($"Master key {wrapped.MasterKeyId} is not loaded; this server has {CurrentKeyId}.");
        }

        return Decrypt(wrappingKey, new SealedItem(wrapped.Nonce, wrapped.Ciphertext, wrapped.Tag), context);
    }

    // A fresh random nonce per encryption. A data key encrypts a handful of items once, and a wrapping key a few
    // thousand keys over its life: both are far below the point where random 96-bit nonces become a concern.
    private static SealedItem Encrypt(byte[] key, ReadOnlySpan<byte> plaintext, byte[] context)
    {
        var nonce = RandomNumberGenerator.GetBytes(NonceBytes);
        var ciphertext = new byte[plaintext.Length];
        var tag = new byte[TagBytes];
        using var aes = new AesGcm(key, TagBytes);
        aes.Encrypt(nonce, plaintext, ciphertext, tag, context);
        return new SealedItem(nonce, ciphertext, tag);
    }

    private static byte[] Decrypt(byte[] key, SealedItem item, byte[] context)
    {
        var plaintext = new byte[item.Ciphertext.Length];
        try
        {
            using var aes = new AesGcm(key, TagBytes);
            aes.Decrypt(item.Nonce, item.Ciphertext, item.Tag, plaintext, context);
            return plaintext;
        }
        catch (Exception e) when (e is CryptographicException or ArgumentException)
        {
            throw new KeyRingException("The material does not open: it was altered, moved, or belongs to another key.", e);
        }
    }

    private static byte[] DataKeyContext(VersionAddress address) =>
        Encoding.UTF8.GetBytes($"secrethive/data-key/v1|{address.ValueId:N}|{address.VersionId:N}");

    private static byte[] ItemContext(VersionAddress address, string slot) =>
        Encoding.UTF8.GetBytes($"secrethive/item/v1|{address.ValueId:N}|{address.VersionId:N}|{slot}");
}
